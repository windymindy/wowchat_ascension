package wowchat.discord

import wowchat.commands.CommandHandler
import wowchat.common._
import com.typesafe.scalalogging.StrictLogging
import com.vdurmont.emoji.EmojiParser
import net.dv8tion.jda.api.JDABuilder
import net.dv8tion.jda.api.JDA.Status
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel
import net.dv8tion.jda.api.entities.{Activity, Message, MessageEmbed, MessageType}
import net.dv8tion.jda.api.entities.channel.ChannelType
import net.dv8tion.jda.api.entities.Activity.ActivityType
import net.dv8tion.jda.api.events.StatusChangeEvent
import net.dv8tion.jda.api.events.session.ShutdownEvent
import net.dv8tion.jda.api.events.message.MessageReceivedEvent
import net.dv8tion.jda.api.hooks.ListenerAdapter
import net.dv8tion.jda.api.requests.{CloseCode, GatewayIntent, RestAction}
import net.dv8tion.jda.api.EmbedBuilder
import net.dv8tion.jda.api.utils.MemberCachePolicy
import net.dv8tion.jda.api.utils.cache.CacheFlag
import wowchat.game.GamePackets

import scala.collection.JavaConverters._
import scala.collection.mutable

case class GuildDashboard(online: Boolean, guild: String, realm: String, members: Seq[(String, String, String)])

class Discord(discordConnectionCallback: CommonConnectionCallback) extends ListenerAdapter
  with GamePackets with StrictLogging {

  private val jda = JDABuilder
    .createDefault(Global.config.discord.token, GatewayIntent.GUILD_MESSAGES, GatewayIntent.MESSAGE_CONTENT, GatewayIntent.GUILD_EXPRESSIONS, GatewayIntent.GUILD_MEMBERS, GatewayIntent.GUILD_PRESENCES)
    .setMemberCachePolicy(MemberCachePolicy.ALL)
    .disableCache(CacheFlag.VOICE_STATE)
    .disableCache(CacheFlag.SCHEDULED_EVENTS)
    .addEventListeners(this)
    .build

  private val messageResolver = MessageResolver(jda)

  private var lastStatus: Option[Activity] = None
  private var firstConnect = true

  private var guildDashboard = new GuildDashboard_

  def changeStatus(gameType: ActivityType, message: String): Unit = {
    lastStatus = Some(Activity.of(gameType, message))
    jda.getPresence.setActivity(lastStatus.get)
  }

  def changeGuildStatus(message: String): Unit = {
    changeStatus(ActivityType.WATCHING, message)
  }

  def changeRealmStatus(message: String): Unit = {
    changeStatus(ActivityType.CUSTOM_STATUS, message)
  }

  def sendMessageFromWow(from: Option[String], message: String, wowType: Byte, wowChannel: Option[String], format: Option[String]): Unit = {
    Global.wowToDiscord.get((wowType, wowChannel.map(_.toLowerCase))).foreach(discordChannels => {
      val parsedLinks = messageResolver.resolveEmojis(messageResolver.stripColorCoding(messageResolver.stripTextureCoding(messageResolver.resolveLinks(message))))

      discordChannels.foreach {
        case (channel, channelConfig) =>
          var errors = mutable.ArrayBuffer.empty[String]
          val parsedResolvedTags = from.map(_ => {
            messageResolver.resolveTags(channel, parsedLinks, errors += _)
          })
            .getOrElse(parsedLinks)
            .replace("`", "\\`")
            .replace("*", "\\*")
            .replace("_", "\\_")
            .replace("~", "\\~")

          val formatted = format.getOrElse(channelConfig.format)
            .replace("%time", Global.getTime)
            .replace("%user", from.getOrElse(""))
            .replace("%message", parsedResolvedTags)
            .replace("%target", wowChannel.getOrElse(""))

          val filter = shouldFilter(channelConfig.filters, formatted)
          logger.info(s"${if (filter) "FILTERED " else ""}WoW->Discord(${channel.getName}) $formatted")
          if (!filter) {
            channel.sendMessage(formatted).queue()
          }
          if (Global.config.discord.enableTagFailedNotifications) {
            errors.foreach(error => {
              Global.game.foreach(_.sendMessageToWow(ChatEvents.CHAT_MSG_WHISPER, error, from))
              channel.sendMessage(error).queue()
            })
          }
      }
    })
  }

  def sendGuildNotification(eventKey: String, message: String): Unit = {
    Global.guildEventsToDiscord
      .getOrElse(eventKey, Global.wowToDiscord.getOrElse(
          (ChatEvents.CHAT_MSG_GUILD, None), mutable.Set.empty
        ).map(_._1)
      )
      .foreach(channel => {
        logger.info(s"WoW->Discord(${channel.getName}) $message")
        channel.sendMessage(message).queue()
      })
  }

  def sendAchievementNotification(name: String, achievementId: Int): Unit = {
    val notificationConfig = Global.config.guildConfig.notificationConfigs("achievement")
    if (!notificationConfig.enabled) {
      return
    }

    Global.wowToDiscord.get((ChatEvents.CHAT_MSG_GUILD, None))
      .foreach(_.foreach {
        case (discordChannel, _) =>
          val formatted = notificationConfig
            .format
            .replace("%time", Global.getTime)
            .replace("%user", name)
            .replace("%achievement", messageResolver.resolveAchievementId(achievementId))

          discordChannel.sendMessage(formatted).queue()
      })
  }

  def sendGuildDashboard(dashboard: GuildDashboard, timestamp: Long): Unit = {
    guildDashboard.send(dashboard, timestamp)
  }

  def sendGuildDashboardDisconnected(timestamp: Long): Unit = {
    guildDashboard.sendDisconnected(timestamp)
  }

  override def onStatusChange(event: StatusChangeEvent): Unit = {
    event.getNewStatus match {
      case Status.CONNECTED =>
        lastStatus.foreach(game => changeStatus(game.getType, game.getName))
        // this is a race condition if already connected to wow, reconnect to discord, and bot tries to send
        // wow->discord message. alternatively it was throwing already garbage collected exceptions if trying
        // to use the previous connection's channel references. I guess need to refill these maps on discord reconnection
        Global.discordToWow.clear
        Global.wowToDiscord.clear
        Global.guildEventsToDiscord.clear
        guildDashboard.clear()

        // getNext seq of needed channels from config
        val configChannels = Global.config.channels.map(channelConfig => {
          channelConfig.discord.channel.toLowerCase -> channelConfig
        })
        val configChannelsNames = configChannels.map(_._1)

        val discordTextChannels = event.getEntity.getTextChannels.asScala
        val eligibleDiscordChannels = discordTextChannels
          .filter(channel =>
            configChannelsNames.contains(channel.getName.toLowerCase) ||
            configChannelsNames.contains(channel.getId)
          )

        // build directional maps
        eligibleDiscordChannels.foreach(channel => {
          configChannels
            .filter {
              case (name, _) =>
                name.equalsIgnoreCase(channel.getName) ||
                name == channel.getId
            }
            .foreach {
              case (name, channelConfig) =>
                if (channelConfig.chatDirection == ChatDirection.both ||
                  channelConfig.chatDirection == ChatDirection.discord_to_wow) {
                  Global.discordToWow.addBinding(
                    name.toLowerCase, channelConfig.wow
                  )
                }

                if (channelConfig.chatDirection == ChatDirection.both ||
                  channelConfig.chatDirection == ChatDirection.wow_to_discord) {
                  Global.wowToDiscord.addBinding(
                    (channelConfig.wow.tp, channelConfig.wow.channel.map(_.toLowerCase)),
                    (channel, channelConfig.discord)
                  )
                }
            }
          })

        // build guild notification maps
        val guildEventChannels = Global.config.guildConfig.notificationConfigs
          .filter {
            case (_, notificationConfig) =>
              notificationConfig.enabled
          }
          .flatMap {
            case (key, notificationConfig) =>
              notificationConfig.channel.map(key -> _)
          }

        discordTextChannels.foreach(channel => {
          guildEventChannels
            .filter {
              case (_, name) =>
                name.equalsIgnoreCase(channel.getName) ||
                name == channel.getId
            }
            .foreach {
              case (notificationKey, _) =>
                Global.guildEventsToDiscord.addBinding(notificationKey, channel)
            }
        })

        if (Global.config.dashboard.enabled) {
          guildDashboard.channel = discordTextChannels.find(
            channel => {
              Global.config.dashboard.channel.equalsIgnoreCase(channel.getName) ||
              Global.config.dashboard.channel == channel.getId
            }
          )
        }

        if (Global.discordToWow.nonEmpty || Global.wowToDiscord.nonEmpty) {
          if (firstConnect) {
            discordConnectionCallback.connected
            firstConnect = false
          } else {
            discordConnectionCallback.reconnected
          }
        } else {
          logger.error("No discord channels configured!")
        }
      case Status.DISCONNECTED =>
        discordConnectionCallback.disconnected
      case _ =>
    }
  }

  override def onShutdown(event: ShutdownEvent): Unit = {
    event.getCloseCode match {
      case CloseCode.DISALLOWED_INTENTS =>
        logger.error("Per new Discord rules, you must check the PRESENCE INTENT, SERVER MEMBERS INTENT, and MESSAGE CONTENT INTENT boxes under \"Privileged Gateway Intents\" for this bot in the developer portal. You can find more info at https://discord.com/developers/docs/topics/gateway#privileged-intents")
      case _ =>
    }
  }

  override def onMessageReceived(event: MessageReceivedEvent): Unit = {
    // ignore messages received from self
    if (event.getAuthor.getIdLong == jda.getSelfUser.getIdLong) {
      return
    }

    // ignore messages from non-text channels
    if (event.getChannelType != ChannelType.TEXT) {
      return
    }

    // ignore non-default messages
    val messageType = event.getMessage.getType
    if (messageType != MessageType.DEFAULT && messageType != MessageType.INLINE_REPLY) {
      return
    }

    val channel = event.getChannel
    val channelId = channel.getId
    val channelName = event.getChannel.getName.toLowerCase
    val effectiveName = event.getMember.getEffectiveName
    val message = (sanitizeMessage(event.getMessage.getContentDisplay) +: event.getMessage.getAttachments.asScala.map(_.getUrl))
      .filter(_.nonEmpty)
      .mkString(" ")
    val enableCommandsChannels = Global.config.discord.enableCommandsChannels
    logger.debug(s"RECV DISCORD MESSAGE: [${channel.getName}] [$effectiveName]: $message")
    if (message.isEmpty) {
      logger.error(s"Received a message in channel ${channel.getName} but the content was empty. You likely forgot to enable MESSAGE CONTENT INTENT for your bot in the Discord Developers portal.")
    }

    if ((enableCommandsChannels.nonEmpty && !enableCommandsChannels.contains(channelName)) || !CommandHandler(channel, message)) {
      // send to all configured wow channels
      Global.discordToWow
        .get(channelName)
        .fold(Global.discordToWow.get(channelId))(Some(_))
        .foreach(_.foreach(channelConfig_ => {
          val (finalMessages, channelConfig) = if (shouldSendDirectly(message)) {
            (Seq(message), channelConfig_)
          } else {
            val (message_, channelConfig) = preprocessMessage(message, channelConfig_)
            (splitUpMessage(channelConfig.format, effectiveName, message_), channelConfig)
          }

          finalMessages.foreach(finalMessage => {
            val filter = shouldFilter(channelConfig.filters, finalMessage)
            logger.info(s"${if (filter) "FILTERED " else ""}Discord->WoW(${
              channelConfig.channel.getOrElse(ChatEvents.valueOf(channelConfig.tp))
            }) $finalMessage")
            if (!filter) {
              Global.game.fold(logger.error("Cannot send message! Not connected to WoW!"))(handler => {
                handler.sendMessageToWow(channelConfig.tp, finalMessage, channelConfig.channel)
              })
            }
          })
        }))
    }
  }

  def shouldSendDirectly(message: String): Boolean = {
    val discordConf = Global.config.discord
    val trimmed = message.drop(1).toLowerCase

    message.startsWith(".") &&
    discordConf.enableDotCommands &&
      (
        discordConf.dotCommandsWhitelist.isEmpty ||
        discordConf.dotCommandsWhitelist.contains(trimmed) ||
        // Theoretically it would be better to construct a prefix tree for this.
        !discordConf.dotCommandsWhitelist.forall(item => {
          if (item.endsWith("*")) {
            !trimmed.startsWith(item.dropRight(1).toLowerCase)
          } else {
            true
          }
        })
      )
  }

  def shouldFilter(filtersConfig: Option[FiltersConfig], message: String): Boolean = {
    filtersConfig
      .fold(Global.config.filters)(Some(_))
      .exists(filters => filters.enabled && filters.patterns.exists(message.matches))
  }

  def sanitizeMessage(message: String): String = {
    EmojiParser.parseToAliases(message, EmojiParser.FitzpatrickAction.REMOVE)
  }

  def preprocessMessage(message: String, channelConfig: WowChannelConfig): (String, WowChannelConfig) = {
    if (channelConfig.tp != ChatEvents.CHAT_MSG_WHISPER) {
      return (message, channelConfig)
    }
    if (!message.regionMatches(true, 0, "/w ", 0, "/w ".length)) {
      return ("", channelConfig)
    }
    val message1 = message.substring("/w ".length)
    val firstSpace = message1.indexOf(' ')
    if (firstSpace == -1) {
      return ("", channelConfig)
    }
    val target = message1.substring(0, firstSpace)
    if (target.length < 3 || target.length > 12 || !target.matches("[a-zA-Z]+") || target.equalsIgnoreCase(Global.config.wow.character)) {
      return ("", channelConfig)
    }
    val message2 = message1.substring(firstSpace + 1)
    val channelConfig_ = channelConfig.copy(channel = Some(target))
    (message2, channelConfig_)
  }

  def splitUpMessage(format: String, name: String, message: String): Seq[String] = {
    val retArr = mutable.ArrayBuffer.empty[String]
    val maxTmpLen = 255 - format
      .replace("%time", Global.getTime)
      .replace("%user", name)
      .replace("%message", "")
      .length

    var tmp = message
    while (tmp.length > maxTmpLen) {
      val subStr = tmp.substring(0, maxTmpLen)
      val spaceIndex = subStr.lastIndexOf(' ')
      tmp = if (spaceIndex == -1) {
        retArr += subStr
        tmp.substring(maxTmpLen)
      } else {
        retArr += subStr.substring(0, spaceIndex)
        tmp.substring(spaceIndex + 1)
      }
    }

    if (tmp.nonEmpty) {
      retArr += tmp
    }

    retArr
      .map(message => {
        val formatted = format
          .replace("%time", Global.getTime)
          .replace("%user", name)
          .replace("%message", message)

        // If the final formatted message is a dot command, it should be disabled. Add a space in front.
        if (formatted.startsWith(".")) {
          s" $formatted"
        } else {
          formatted
        }
      })
  }

  private class GuildDashboard_ {

    var channel: Option[TextChannel] = None
    private var published: Option[Vector[Message]] = None
    private var last: Option[GuildDashboard] = None
    private var pending: Option[(GuildDashboard, Long)] = None
    private var sending: Boolean = false

    def clear(): Unit = {
      channel = None
      published = None
      sending = false
    }

    def send(dashboard: GuildDashboard, timestamp: Long): Unit = {
      if (channel.isEmpty) {
        return
      }

      if (published.isEmpty) {
        if (!throttle_(dashboard, timestamp)) {
          return
        }
        findPublished(dashboard, checkThrottled, checkThrottled)
        return
      }

      if (last.isDefined && last.get.equals(dashboard)) {
        return
      }
      if (!throttle(dashboard, timestamp)) {
        return
      }
      publish(
        dashboard, timestamp,
        () => {
          last = Some(dashboard)
          checkThrottled()
        },
        () => {
          published = None
          checkThrottled()
        }
      )
    }

    def sendDisconnected(timestamp: Long): Unit = {
      if (last.isEmpty || !last.get.online) {
        return
      }
      val dashboard = last.get.copy(online = false)
      sendGuildDashboard(dashboard, timestamp)
    }

    private def throttle(dashboard: GuildDashboard, timestamp: Long): Boolean = {
      if (sending) {
        pending = Some(dashboard, timestamp)
        return false
      }
      sending = true
      true
    }

    private def throttle_(dashboard: GuildDashboard, timestamp: Long): Boolean = {
      pending = Some(dashboard, timestamp)
      val result = !sending
      sending = true
      result
    }

    private def checkThrottled(): Unit = {
      sending = false
      if (pending.isEmpty) {
        return
      }
      val (dashboard, timestamp) = pending.get
      pending = None
      send(dashboard, timestamp)
    }

    private def findPublished(dashboard: GuildDashboard, done: () => Unit, failed: () => Unit): Unit = {
      val title = s"${dashboard.guild} — ${dashboard.realm}"
      channel.get.getHistory.retrievePast(10).queue(
        (messages: java.util.List[Message]) => {
          val result = messages.asScala
            .reverse
            .dropWhile(
              message =>
                message.getAuthor.getIdLong != jda.getSelfUser.getIdLong
                  || message.getEmbeds.size != 1
                  || !title.equalsIgnoreCase(message.getEmbeds.get(0).getTitle)
            ).takeWhile(
            message =>
              message.getAuthor.getIdLong == jda.getSelfUser.getIdLong
                && message.getEmbeds.size == 1
                && (title.equalsIgnoreCase(message.getEmbeds.get(0).getTitle) || message.getEmbeds.get(0).getTitle == null)
                && message.getEmbeds.get(0).getDescription.nonEmpty
          ).toVector
          published = Some(result)
          done()
        },
        (error: Throwable) => {
          logger.error("Failed to send the guild dashboard:", error)
          failed()
        }
      )
    }

    private def publish(dashboard: GuildDashboard, timestamp: Long, done: () => Unit, failed: () => Unit): Unit = {
      val messages = published.get
      val messages_ = format(dashboard, timestamp, messages.size)
      if (messages.size == messages_.size) {
        val edit = messages.zip(messages_).map(
          (i) => {
            val message = i._1
            val message_ = i._2
            message.editMessageEmbeds(message_)
          }
        )
        new Actions().queue(
          edit,
          done,
          (error) => {
            logger.error("Failed to send the guild dashboard:", error)
            failed()
          }
        )
      } else {
        published = None
        val delete_ = messages.map(i => i.delete())
        val send_ = () => {
          val send_ = messages_.map(message_ => channel.get.sendMessageEmbeds(message_))
          new Actions().queue(
            send_,
            done,
            (error) => {
              logger.error("Failed to send the guild dashboard:", error)
              failed()
            }
          )
        }
        if (!delete_.isEmpty) {
          new Actions().queue(
            delete_,
            send_,
            (_) => {
              send_()
            }
          )
        } else {
          send_()
        }
      }
    }

    private def format(value: GuildDashboard, timestamp: Long, previous: Int): Seq[MessageEmbed] = {
      val group = 13
      val block = 5

      def pad1(value: String, width: Int): String = {
        value.padTo(width, '\u00a0')
      }

      def pad2(value: String, width: Int): String = {
        value.padTo(width, '\u3164')
      }

      def color_pad(value: String, width: Int): String = {
        if (value.length < 2)
          return value.padTo(width, '\u00a0')
        // https://gist.github.com/kkrypt0nn/a02506f3712ff2d1c8ca7c9e0aed7c06
        // https://message.style/app/tools/colored-text
        val colors = Vector(
          /*"30",*/ "31", "32", "33", "34", "35", "36", "37",
          /*"40;30",*/ "40;31", "40;32", "40;33", "40;34", "40;35", "40;36", "40;37",
          "41;30", /*"41;31", "41;32", "41;33", "41;34", "41;35", "41;36",*/ "41;37",
          /*"42;30", "42;31", "42;32", "42;33", "42;34", "42;35", "42;36", "42;37",*/
          /*"43;30", "43;31", "43;32", "43;33", "43;34", "43;35", "43;36", "43;37",*/
          /*"44;30", "44;31", "44;32", "44;33", "44;34", "44;35", "44;36", "44;37",*/
          /*"45;30", "45;31", "45;32", "45;33", "45;34", "45;35", "45;36", "45;37",*/
          "46;30", "46;31", /*"46;32", "46;33", "46;34",*/ "46;35", /*"46;36",*/ "46;37",
          "47;30", "47;31", "47;32", "47;33", "47;34", "47;35", "47;36", /*"47;37"*/
        )
        val color = colors((value(0) + value(value.length - 1) + value.length) % colors.length)
        "\u001b[" + color + "m" + value + "\u001b[0m" + "".padTo(width - value.length, '\u00a0')
      }

      val title = s"${value.guild} — ${value.realm}"
      var description =
        if (value.online)
          s":green_circle: ${value.members.size} online"
        else
          s":red_circle: ${value.members.size} were online"
      description = pad2(description, 28) + s"<t:${timestamp / 1000L}:R>"
      val members_header = pad2("", 3) + "**Name**" + pad2("", 3) + "**Level**" + pad2("", 3) + "**Area**"
      val members = value.members.grouped(group).padTo(1, Seq(("—", "", ""))).map(
        i => {
          // name 12 + color 12 + space 1 + level 3 + area 24 = 52
          val members = i
            .map(i => color_pad(i._1.take(12), 13) + pad1(i._2.take(3), 3) + pad1(i._3.take(24), 24))
            .padTo(group, "\u3164")
            .mkString("\n")
          s"```ansi\n${members}\n```"
        }
      ).grouped(block).toSeq
      var result = Vector.empty[MessageEmbed]
      members.take(1).foreach(
        (members) => {
          val result_ = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description + "\n\n" + members_header + "\n")
          members.foreach((members) => {
            result_.appendDescription(members)
          })
          result = result :+ result_.build()
        }
      )
      members.drop(1).foreach(
        (members) => {
          val result_ = new EmbedBuilder()
          members.foreach((members) => {
            result_.appendDescription(members)
          })
          result = result :+ result_.build()
        }
      )
      result.padTo(previous, new EmbedBuilder().setDescription(pad2("", 1)).build())
    }
  }

  private class Actions {

    private var instance: AnyRef = _

    def queue[T](actions: Seq[RestAction[T]], done: () => Unit, failed: (Throwable) => Unit): Unit = {
      val instance_ = new AnyRef
      instance = instance_
      var count = actions.size
      actions.foreach(
        (i) => {
          i.queue(
            (_: T) => {
              if (instance == instance_) {
                count = count - 1
                if (count <= 0) {
                  instance = null
                  done()
                }
              }
            },
            (error: Throwable) => {
              if (instance == instance_) {
                instance = null
                failed(error)
              }
            }
          )
        }
      )
    }
  }
}

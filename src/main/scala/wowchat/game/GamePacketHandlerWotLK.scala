package wowchat.game

import java.nio.charset.Charset
import java.security.MessageDigest

import io.netty.buffer.{ByteBuf, PooledByteBufAllocator}

import wowchat.common._

import scala.util.Random

class GamePacketHandlerWotLK(realmId: Int, realmName: String, sessionKey: Array[Byte], gameEventCallback: CommonConnectionCallback)
  extends GamePacketHandlerTBC(realmId, realmName, sessionKey, gameEventCallback) with GamePacketsWotLK {

  override protected val addonInfo: Array[Byte] = Array(
    0x9E, 0x02, 0x00, 0x00, 0x78, 0x9C, 0x75, 0xD2, 0xC1, 0x6A, 0xC3, 0x30, 0x0C, 0xC6, 0x71, 0xEF,
    0x29, 0x76, 0xE9, 0x9B, 0xEC, 0xB4, 0xB4, 0x50, 0xC2, 0xEA, 0xCB, 0xE2, 0x9E, 0x8B, 0x62, 0x7F,
    0x4B, 0x44, 0x6C, 0x39, 0x38, 0x4E, 0xB7, 0xF6, 0x3D, 0xFA, 0xBE, 0x65, 0xB7, 0x0D, 0x94, 0xF3,
    0x4F, 0x48, 0xF0, 0x47, 0xAF, 0xC6, 0x98, 0x26, 0xF2, 0xFD, 0x4E, 0x25, 0x5C, 0xDE, 0xFD, 0xC8,
    0xB8, 0x22, 0x41, 0xEA, 0xB9, 0x35, 0x2F, 0xE9, 0x7B, 0x77, 0x32, 0xFF, 0xBC, 0x40, 0x48, 0x97,
    0xD5, 0x57, 0xCE, 0xA2, 0x5A, 0x43, 0xA5, 0x47, 0x59, 0xC6, 0x3C, 0x6F, 0x70, 0xAD, 0x11, 0x5F,
    0x8C, 0x18, 0x2C, 0x0B, 0x27, 0x9A, 0xB5, 0x21, 0x96, 0xC0, 0x32, 0xA8, 0x0B, 0xF6, 0x14, 0x21,
    0x81, 0x8A, 0x46, 0x39, 0xF5, 0x54, 0x4F, 0x79, 0xD8, 0x34, 0x87, 0x9F, 0xAA, 0xE0, 0x01, 0xFD,
    0x3A, 0xB8, 0x9C, 0xE3, 0xA2, 0xE0, 0xD1, 0xEE, 0x47, 0xD2, 0x0B, 0x1D, 0x6D, 0xB7, 0x96, 0x2B,
    0x6E, 0x3A, 0xC6, 0xDB, 0x3C, 0xEA, 0xB2, 0x72, 0x0C, 0x0D, 0xC9, 0xA4, 0x6A, 0x2B, 0xCB, 0x0C,
    0xAF, 0x1F, 0x6C, 0x2B, 0x52, 0x97, 0xFD, 0x84, 0xBA, 0x95, 0xC7, 0x92, 0x2F, 0x59, 0x95, 0x4F,
    0xE2, 0xA0, 0x82, 0xFB, 0x2D, 0xAA, 0xDF, 0x73, 0x9C, 0x60, 0x49, 0x68, 0x80, 0xD6, 0xDB, 0xE5,
    0x09, 0xFA, 0x13, 0xB8, 0x42, 0x01, 0xDD, 0xC4, 0x31, 0x6E, 0x31, 0x0B, 0xCA, 0x5F, 0x7B, 0x7B,
    0x1C, 0x3E, 0x9E, 0xE1, 0x93, 0xC8, 0x8D
  ).map(_.toByte)

  override protected def parseAuthChallenge(msg: Packet): AuthChallengeMessage = {
    val account = Global.config.wow.account

    msg.byteBuf.skipBytes(4) // wotlk
    val serverSeed = msg.byteBuf.readInt
    val clientSeed = Random.nextInt
    val out = PooledByteBufAllocator.DEFAULT.buffer(200, 400)
    out.writeShortLE(0)
    out.writeIntLE(WowChatConfig.getGameBuild)
    out.writeIntLE(0)
    out.writeBytes(account)
    out.writeByte(0)
    out.writeInt(0) // wotlk
    out.writeInt(clientSeed)
    out.writeIntLE(0) // wotlk
    out.writeIntLE(0) // wotlk
    out.writeIntLE(realmId) // wotlk
    out.writeLongLE(3) // wotlk

    val md = MessageDigest.getInstance("SHA1")
    md.update(account)
    md.update(Array[Byte](0, 0, 0, 0))
    md.update(ByteUtils.intToBytes(clientSeed))
    md.update(ByteUtils.intToBytes(serverSeed))
    md.update(sessionKey)
    out.writeBytes(md.digest)

    out.writeBytes(addonInfo)

    AuthChallengeMessage(sessionKey, out)
  }

  override protected def parseNameQuery(msg: Packet): NameQueryMessage = {
    val guid = unpackGuid(msg.byteBuf)

    val nameKnown = msg.byteBuf.readByte // wotlk
    val (name, charClass) = if (nameKnown == 0) {
      val name = msg.readString
      msg.skipString // realm name for cross bg usage

      // wotlk changed the char info to bytes
      msg.byteBuf.skipBytes(1) // race
      msg.byteBuf.skipBytes(1) // gender
      val charClass = msg.byteBuf.readByte
      (name, charClass)
    } else {
      logger.error(s"RECV SMSG_NAME_QUERY - Name not known for guid $guid")
      ("UNKNOWN", 0xFF.toByte)
    }

    NameQueryMessage(guid, name, charClass)
  }

  override protected def parseCharEnum(msg: Packet): Option[CharEnumMessage] = {
    val characterBytes = Global.config.wow.character.toLowerCase.getBytes("UTF-8")
    val charactersNum = msg.byteBuf.readByte

    // only care about guid and name here
    (0 until charactersNum).foreach(i => {
      val guid = msg.byteBuf.readLongLE
      val name = msg.readString
      val race = msg.byteBuf.readByte // will determine what language to use in chat

      msg.byteBuf.skipBytes(1) // class
      msg.byteBuf.skipBytes(1) // gender
      msg.byteBuf.skipBytes(1) // skin
      msg.byteBuf.skipBytes(1) // face
      msg.byteBuf.skipBytes(1) // hair style
      msg.byteBuf.skipBytes(1) // hair color
      msg.byteBuf.skipBytes(1) // facial hair
      msg.byteBuf.skipBytes(1) // level
      msg.byteBuf.skipBytes(4) // zone
      msg.byteBuf.skipBytes(4) // map - could be useful in the future to determine what city specific channels to join

      msg.byteBuf.skipBytes(12) // x + y + z

      val guildGuid = msg.byteBuf.readIntLE
      if (name.toLowerCase.getBytes("UTF-8").sameElements(characterBytes)) {
        return Some(CharEnumMessage(name, guid, race, guildGuid))
      }

      msg.byteBuf.skipBytes(4) // character flags
      msg.byteBuf.skipBytes(4) // character customize flags WotLK only
      msg.byteBuf.skipBytes(1) // first login
      msg.byteBuf.skipBytes(12) // pet info
      msg.byteBuf.skipBytes(19 * 9) // equipment info TBC has 9 slot equipment info
      msg.byteBuf.skipBytes(4 * 9) // bag display for WotLK has all 4 bags
    })
    None
  }

  override protected def parseChatMessage(msg: Packet): Option[ChatMessage] = {
    val tp = msg.byteBuf.readByte

    val lang = msg.byteBuf.readIntLE
    // ignore addon messages
    if (lang == -1) {
      return None
    }

    // ignore messages from itself, unless it is a system message.
    val guid = msg.byteBuf.readLongLE
    if (tp != ChatEvents.CHAT_MSG_SYSTEM && guid == selfCharacterId.get) {
      return None
    }

    msg.byteBuf.skipBytes(4)

    if (msg.id == SMSG_GM_MESSAGECHAT) {
      msg.byteBuf.skipBytes(4)
      msg.skipString
    }

    val channelName = if (tp == ChatEvents.CHAT_MSG_CHANNEL) {
      Some(msg.readString)
    } else {
      None
    }

    // ignore if from an unhandled channel - unless it is a guild achievement message
    if (tp != ChatEvents.CHAT_MSG_GUILD_ACHIEVEMENT && !Global.wowToDiscord.contains((tp, channelName.map(_.toLowerCase)))) {
      return None
    }

    msg.byteBuf.skipBytes(8) // skip guid again

    val txtLen = msg.byteBuf.readIntLE
    val txt = msg.byteBuf.readCharSequence(txtLen - 1, Charset.forName("UTF-8")).toString
    msg.byteBuf.skipBytes(1) // null terminator
    msg.byteBuf.skipBytes(1) // chat tag

    if (tp == ChatEvents.CHAT_MSG_GUILD_ACHIEVEMENT) {
      handleAchievementEvent(guid, msg.byteBuf.readIntLE)
      None
    } else {
      Some(ChatMessage(guid, tp, txt, channelName))
    }
  }

  override protected def parseWorldObjectUpdate(msg: Packet): WorldObjectUpdate = {
    var create = Vector[WorldObjectUpdate.Object]()

    val blockCount = msg.byteBuf.readIntLE
    (0 until blockCount).foreach(
      _ => {
        val blockType = msg.byteBuf.readByte
        blockType match {
          case 0 => { // UPDATETYPE_VALUES
            val guid = unpackGuid(msg.byteBuf)
            parseWorldObjectUpdateFields(msg)
          }
          case 1 => { // UPDATETYPE_MOVEMENT
            val guid = unpackGuid(msg.byteBuf)
            parseWorldObjectUpdateMovement(msg)
          }
          case 2 | 3 => { // UPDATETYPE_CREATE_OBJECT, UPDATETYPE_CREATE_OBJECT2
            val guid = unpackGuid(msg.byteBuf)
            val type_ = msg.byteBuf.readByte
            val movement = parseWorldObjectUpdateMovement(msg)
            parseWorldObjectUpdateFields(msg)

            val self_ = (movement.flags & 0x1) == 0x1 // UPDATEFLAG_SELF
            create = create :+ WorldObjectUpdate.Object(guid, type_, self_, movement)
          }
          case 4 | 5 => { // UPDATETYPE_OUT_OF_RANGE_OBJECTS, UPDATETYPE_NEAR_OBJECTS
            val count = msg.byteBuf.readIntLE
            (0 until count).foreach(_ => { val guid = unpackGuid(msg.byteBuf) })
          }
          case unhandled => {
            logger.error("Failed to parse world object update packet.")
            return WorldObjectUpdate(Vector())
          }
        }
      }
    )
    WorldObjectUpdate(create)
  }

  private def parseWorldObjectUpdateFields(msg: Packet): Unit = {
    val count = msg.byteBuf.readByte
    val counts = (0 until count).map(
      _ => {
        msg.byteBuf.readIntLE
      }
    )
    counts.foreach(
      counts_ => {
        msg.byteBuf.skipBytes(4 * java.lang.Integer.bitCount(counts_))
      }
    )
  }

  private def parseWorldObjectUpdateMovement(msg: Packet): WorldObjectUpdate.Movement = {
    var x: Float = 0
    var y: Float = 0
    var z: Float = 0

    val flags = msg.byteBuf.readChar.reverseBytes
    if ((flags & 0x20) == 0x20) { // UPDATEFLAG_LIVING
      val flags_ = msg.byteBuf.readIntLE
      val flags__ = msg.byteBuf.readChar.reverseBytes
      msg.byteBuf.skipBytes(4)
      x = msg.byteBuf.readFloatLE
      y = msg.byteBuf.readFloatLE
      z = msg.byteBuf.readFloatLE
      msg.byteBuf.skipBytes(4)
      if ((flags_ & 0x200) == 0x200) { // MOVEMENTFLAG_ONTRANSPORT
        unpackGuid(msg.byteBuf)
        msg.byteBuf.skipBytes(4 * 4)
        msg.byteBuf.skipBytes(4)
        msg.byteBuf.skipBytes(1)
        if ((flags__ & 0x400) == 0x400) { // MOVEMENTFLAG2_INTERPOLATED_MOVEMENT
          msg.byteBuf.skipBytes(4)
        }
      }
      if (
        (flags_ & 0x200000) == 0x200000 // MOVEMENTFLAG_SWIMMING
        || (flags_ & 0x2000000) == 0x2000000 // MOVEMENTFLAG_FLYING
        || (flags__ & 0x20) == 0x20 // MOVEMENTFLAG2_ALWAYS_ALLOW_PITCHING
      ) {
        msg.byteBuf.skipBytes(4)
      }
      msg.byteBuf.skipBytes(4)
      if ((flags_ & 0x1000) == 0x1000) { // MOVEMENTFLAG_FALLING
        msg.byteBuf.skipBytes(4 * 4)
      }
      if ((flags_ & 0x4000000) == 0x4000000) { // MOVEMENTFLAG_SPLINE_ELEVATION
        msg.byteBuf.skipBytes(4)
      }
      msg.byteBuf.skipBytes(9 * 4)
      if ((flags_ & 0x8000000) == 0x8000000) { // MOVEMENTFLAG_SPLINE_ENABLED
        val flags___ = msg.byteBuf.readIntLE
        if ((flags___ & 0x20000) == 0x20000) {
          msg.byteBuf.skipBytes(4)
        }
        if ((flags___ & 0x10000) == 0x10000) {
          msg.byteBuf.skipBytes(8)
        }
        if ((flags___ & 0x8000) == 0x8000) {
          msg.byteBuf.skipBytes(3 * 4)
        }
        msg.byteBuf.skipBytes(3 * 4)
        msg.byteBuf.skipBytes(2 * 4)
        msg.byteBuf.skipBytes(2 * 4)
        val splines = msg.byteBuf.readIntLE
        (0 until splines).foreach(_ => { msg.byteBuf.skipBytes(3 * 4) })
        msg.byteBuf.skipBytes(1)
        msg.byteBuf.skipBytes(3 * 4)
      }
    } else {
      if ((flags & 0x100) == 0x100) { // UPDATEFLAG_POSITION
        unpackGuid(msg.byteBuf)
        x = msg.byteBuf.readFloatLE
        y = msg.byteBuf.readFloatLE
        z = msg.byteBuf.readFloatLE
        msg.byteBuf.skipBytes(4 * 4)
        msg.byteBuf.skipBytes(4)
      } else if ((flags & 0x40) == 0x40) { // UPDATEFLAG_STATIONARY_POSITION
        x = msg.byteBuf.readFloatLE
        y = msg.byteBuf.readFloatLE
        z = msg.byteBuf.readFloatLE
        msg.byteBuf.skipBytes(4)
      }
    }

    if ((flags & 0x8) == 0x8) { // UPDATEFLAG_HIGHGUID
      msg.byteBuf.skipBytes(4)
    }
    if ((flags & 0x10) == 0x10) { // UPDATEFLAG_LOWGUID
      msg.byteBuf.skipBytes(4)
    }
    if ((flags & 0x4) == 0x4) { // UPDATEFLAG_HAS_TARGET
      unpackGuid(msg.byteBuf)
    }
    if ((flags & 0x2) == 0x2) { // UPDATEFLAG_TRANSPORT
      msg.byteBuf.skipBytes(4)
    }
    if ((flags & 0x80) == 0x80) { // UPDATEFLAG_VEHICLE
      msg.byteBuf.skipBytes(2 * 4)
    }
    if ((flags & 0x200) == 0x200) { // UPDATEFLAG_ROTATION
      msg.byteBuf.skipBytes(8)
    }

    WorldObjectUpdate.Movement(flags, x, y, z)
  }

  protected def handleAchievementEvent(guid: Long, achievementId: Int): Unit = {
    // This is a guild event so guid MUST be in roster already
    // (unless some weird edge case -> achievement came before roster update)
    guildRoster.get(guid).foreach(player => {
      Global.discord.sendAchievementNotification(player.name, achievementId)
    })
  }

  // saving those single 0 bytes like whoa
  private def unpackGuid(byteBuf: ByteBuf): Long = {
    val set = byteBuf.readByte

    (0 until 8).foldLeft(0L) {
      case (result, i) =>
        val onBit = 1 << i
        if ((set & onBit) == onBit) {
          result | ((byteBuf.readByte & 0xFFL) << (i * 8))
        } else {
          result
        }
    }
  }
}

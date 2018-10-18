package wowchat.game

trait GamePacketsMoP extends GamePacketsCataclysm {

  // this might just use the same bit obfuscating as some of the other variables like player guid
  // but mangos hardcodes the values.
//  val WOW_CONNECTION = 0x4F57 // same hack as in mangos :D
//
//  val CMSG_MESSAGECHAT_AFK = 0x0D44
//  val CMSG_MESSAGECHAT_BATTLEGROUND = 0x2156
//  val CMSG_MESSAGECHAT_CHANNEL = 0x1D44
//  val CMSG_MESSAGECHAT_DND = 0x2946
//  val CMSG_MESSAGECHAT_EMOTE = 0x1156
//  val CMSG_MESSAGECHAT_GUILD = 0x3956
//  val CMSG_MESSAGECHAT_OFFICER = 0x1946
//  val CMSG_MESSAGECHAT_PARTY = 0x1D46
//  val CMSG_MESSAGECHAT_SAY = 0x1154
//  val CMSG_MESSAGECHAT_WHISPER = 0x0D56
//  val CMSG_MESSAGECHAT_YELL = 0x3544

  override val CMSG_CHAR_ENUM = 0x00E0
  override val SMSG_CHAR_ENUM = 0x11C3
  override val CMSG_PLAYER_LOGIN = 0x158F
  override val CMSG_LOGOUT_REQUEST = 0x1349
  override val CMSG_NAME_QUERY = 0x0328
  override val SMSG_NAME_QUERY = 0x6E04
  override val CMSG_WHO = 0x18A3
  override val SMSG_WHO = 0x161B
  override val CMSG_GUILD_ROSTER = 0x1459
  override val SMSG_GUILD_ROSTER = 0x0BE0
  override val SMSG_GUILD_EVENT = 0x0705
  override val SMSG_CHATMESSAGE = 0x2026
  override val CMSG_JOIN_CHANNEL = 0x0156
  override val SMSG_CHANNEL_NOTIFY = 0x0825

  override val SMSG_NOTIFICATION = 0x0C2A
  override val CMSG_PING = 0x0012
  override val SMSG_AUTH_CHALLENGE = 0x0949
  override val CMSG_AUTH_CHALLENGE = 0x00B2
  override val SMSG_AUTH_RESPONSE = 0x0ABA
  override val SMSG_LOGIN_VERIFY_WORLD = 0x1C0F

  override val SMSG_WARDEN_DATA = 0x0C0A
  override val CMSG_WARDEN_DATA = 0x1816

  override val SMSG_TIME_SYNC_REQ = 0x1A8F
  override val CMSG_TIME_SYNC_RESP = 0x01DB
}

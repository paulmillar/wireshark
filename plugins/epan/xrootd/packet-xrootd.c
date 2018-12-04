#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include "packet-xrootd.h"

#define XROOTD_PORT 1094

static int proto_xrootd = -1;

/**
 *  Initial request from client is 20 bytes.
 */
#define HANDSHAKE_REQUEST_LEN 20

/**
 *  Requests are always at least 24 bytes.  The length is declared
 *  within those 24 bytes.
 */
#define REQUEST_FRAME_LEN 24

/**
 *  Responses are always at least 8 bytes.  The length is declared
 *  within those 8 bytes.
 */
#define RESPONSE_FRAME_LEN 8

static int dissect_xrootd_message(tvbuff_t *tvb, packet_info *pinfo _U_,
				  proto_tree *tree _U_, void *data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "XROOTD");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  /* TODO: implement dissecting code */
  return tvb_captured_length(tvb);
}

static guint get_xrootd_message_length(packet_info *pinfo _U_, tvbuff_t *tvb,
				       int offset, void *data _U_)
{
  /* Once we have sufficient bytes to determine the length, what is the length? */
  return (guint) 4;
}

static int dissect_xrootd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_,
			  void *data _U_)
{
  /*  FIXME: the framing in xrootd is not consistent:
   *
   *      Client initially sends a 20 byte sequence.
   *
   *      Server replies with either a 12 byte or a "normal" response
   *
   *      Client requests are at least 24 bytes
   *
   *      Server responses are at least 8 bytes
   *
   */
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, RESPONSE_FRAME_LEN,
		   get_xrootd_message_length, dissect_xrootd_message, data);

  return tvb_captured_length(tvb);
}

void proto_register_xrootd(void)
{
  proto_xrootd = proto_register_protocol(
					 "xrootd protocol", /* name */
					 "XROOTD", /* short name */
					 "xrootd" /* abbrev */
				     );
}

void proto_reg_handoff_xrootd(void)
{
  static dissector_handle_t xrootd_handle;

  xrootd_handle = create_dissector_handle(dissect_xrootd, proto_xrootd);
  dissector_add_uint("tcp.port", XROOTD_PORT, xrootd_handle);
}

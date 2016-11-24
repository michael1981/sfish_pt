#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35297);
  script_version("$Revision: 1.2 $");

  script_name(english:"SSL Service Requests Client Certificate");
  script_summary(english:"Checks for a certificate request in a SSL Server Hello");

 script_set_attribute(attribute:"synopsis", value:
"The remote service requests an SSL client certificate." );
 script_set_attribute(attribute:"description", value:
"The remote service encrypts communications using SSL / TLS, requests a
client certificate, and may require a valid certificate in order to
establish a connection to the underlying service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 443, 1241);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = get_kb_list("Services/unknown");
}
else ports = make_list();
ports = add_port_in_list(list:ports, port:443);
ports = add_port_in_list(list:ports, port:1241);


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Loop through each port.
foreach port (ports)
{
  # If it's unknown, open, and not currently detected as SSL / TLS...
  if (
    service_is_unknown(port:port) && 
    get_tcp_port_state(port) &&
    get_kb_item("Transports/TCP/"+port) == 1
  )
  {
    # nb: SSLv2 requests client certificates in a totally different fashion,
    #     which we don't support.
    foreach encaps (make_list(ENCAPS_SSLv3, ENCAPS_TLSv1))
    {
      soc = open_sock_tcp(port, transport:ENCAPS_IP);
      if (!soc) continue;

      if (encaps == ENCAPS_SSLv3)      ssl_ver = raw_string(0x03, 0x00);
      else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);

      helo = client_hello(
        version    : ssl_ver,
        v2hello    : FALSE
      );
      send(socket:soc, data:helo);

      client_cert_req = FALSE;
      done = FALSE;
      while (!done)
      {
        res = recv_ssl(socket:soc);
        if (isnull(res)) done = TRUE;
        else
        {
          msg_type = getbyte(blob:res, pos:0);
          msg_len = getword(blob:res, pos:3);
          # nb: msg_len doesn't include the first 5 bytes.
          msg = substr(res, 0, msg_len+5-1);
          res = substr(res, msg_len+5);

          # Handshake message.
          if (msg_type == 22 && strlen(msg) > 3)
          {
            while (!done && strlen(msg) > 8)
            {
              hand_type = getbyte(blob:msg, pos:5);
              hand_len = getbyte(blob:msg, pos:6)*65536 + getword(blob:msg, pos:7);
              # nb: hand_len doesn't include the first 4 bytes.
              hand = substr(msg, 5, hand_len+4+5-1);

              # Certificate request.
              if (hand_type == 13)
              {
                client_cert_req = TRUE;
                done = TRUE;
              }
              # Server hello done.
              else if (hand_type == 14) done = TRUE;
              # Finished.
              else if (hand_type == 20) done = TRUE;

              msg = substr(msg, hand_len+4);
            }
          }
        }
      }
      close(soc);

      if (client_cert_req)
      {
        set_kb_item(name:"Transport/SSL", value:port);
        replace_or_set_kb_item(name:"Transports/TCP/"+port, value:encaps);

        info = "";
        if (encaps == ENCAPS_SSLv3) info = 'An SSLv3';
        else if (encaps == ENCAPS_TLSv1) info = 'A TLSv1';

        if (report_verbosity > 0 && info)
        {
          info += ' server is listening on this port.\n';
          security_note(port:port, extra:'\n'+info);
        }
        else security_note(port);

        break;
      }
    }
  }
}

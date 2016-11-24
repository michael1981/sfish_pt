#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11154);
 script_version ("$Revision: 1.50 $");

 script_name(english:"Unknown Service Detection: Banner Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"There is an unknown service running on the remote host." );
 script_set_attribute(attribute:"description", value:
"Nessus was unable to identify a service on the remote host even though
it returned a banner of some type." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 script_summary(english:"Displays the unknown services banners");
 script_category(ACT_END); 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie(
   "PC_anywhere_tcp.nasl",
   "SHN_discard.nasl",
   "X.nasl",
   "apcnisd_detect.nasl",
   "alcatel_backdoor_switch.nasl",
   "asip-status.nasl",
   "auth_enabled.nasl",
   "bugbear.nasl",
   "cifs445.nasl",
   "cp-firewall-auth.nasl",
   "dcetest.nasl",
   "dns_server.nasl",
   "echo.nasl",
   "find_service1.nasl",
   "find_service2.nasl",
   "mldonkey_telnet.nasl",
   "mssqlserver_detect.nasl",
   "mysql_version.nasl",
   "nessus_detect.nasl",
   "qmtp_detect.nasl",
   "radmin_detect.nasl",
   "rpc_portmap.nasl",
   "rpcinfo.nasl",
   "rsh.nasl",
   "rtsp_detect.nasl",
   "telnet.nasl",
   "xtel_detect.nasl",
   "xtelw_detect.nasl");
   if (NASL_LEVEL >= 3000)
   {
    script_dependencies (
    "aximilter_detect.nasl",
    "cacam_detect.nasl",
    "dotnet_remoting_services_detect.nasl",
    "hp_openview_ovalarmsrv.nasl",
    "hp_openview_ovtopmd.nasl",
    "hp_openview_ovuispmd.nasl",
    "hp_data_protector_installed.nasl",
    "ipswitch_imclient_detect.nasl",
    "ipswitch_imserver_detect.nasl",
    "landesk_remote_control_detect.nbin",
    "lisa_detect.nasl",
    "nagios_statd_detect.nasl",
    "perforce_server_detect.nasl",
    "quote.nasl",
    "veritas_agent_detect.nasl",
    "veritas_netbackup_detect.nasl",
    "veritas_netbackup_vmd_detect.nasl",
    "xmpp_server_detect.nasl",
    "zebedee_detect.nasl",
    "zenworks_rma_detect.nasl"
     );
   }
 script_require_ports("Services/unknown");
 exit(0);
}

#
include("misc_func.inc");
include("dump.inc");

if ( get_kb_item("global_settings/disable_service_discovery") ) exit(0);


port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (port == 139) exit(0);	# Avoid silly messages
if (! service_is_unknown(port: port)) exit(0);

a = get_unknown_banner2(port: port, dontfetch: 1);
if (isnull(a)) exit(0);
banner = a[0]; type = a[1];
if (isnull(banner)) exit(0);

h = hexdump(ddata: banner);
if( strlen(banner) >= 3 )
{
  # See if the service is maybe SSL-wrapped.
  test_ssl = get_preference("Service detection[radio]:Test SSL based services");
  encaps = get_kb_item("Transports/TCP/"+port);

  if (
    (strlen(test_ssl) && "All" >!< test_ssl) &&
    encaps == ENCAPS_IP &&
    (
      # nb: TLSv1 alert of some type.
      stridx(banner, '\x15\x03\x01\x00\x02') == 0 ||
      # nb: TLSv1 handshake.
      stridx(banner, '\x16\x03\x01') == 0 ||
      # nb: SSLv3 handshake.
      stridx(banner, '\x16\x03\x00') == 0 ||
      # nb: SSLv2 alert of some type.
      stridx(banner, '\x80\x03\x00\x00\x01') == 0
    )
  )
  {
    info = string(
      "The service on this port appears to be encrypted with SSL. If you\n",
      "would like Nessus to try harder to detect it, change the 'Test SSL\n",
      "based services' preference to 'All' and re-run the scan.\n"
    );
  }
  else
  {
    h = str_replace(find:'\n', replace:'\n           ', string:h);
    info = string(
      "If you know what this service is, please send a description along\n",
      "with the following output to svc-signatures@nessus.org :\n",
      "\n",
      "  Port :   ", port, "\n",
      "  Type :   ", type, "\n",
      "  Banner : \n", h, "\n"
    );
  }
  report = string(
    "\n",
    info
  );
  security_note(port:port, extra:report);
}

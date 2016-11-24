#
# (C) Tenable Network Security, Inc.
#
# SinFP is a fingerprinting tool written by GomoR and available
# at http://www.gomor.org/cgi-bin/sinfp.pl
#
# This plugin is a white-room reimplementation of the SinFP methodology 
#
ENGINE_VERSION = 7;


include("compat.inc");

if (description)
{
  script_id(25250);
  script_version("$Revision: 1.44 $");

  name["english"] = "OS Identification : SinFP";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating sytem using
SinFP technique." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type 
and version by using the same technique as SinFP." );
 script_set_attribute(attribute:"see_also", value:"http://www.gomor.org/cgi-bin/sinfp.pl" );
  script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007 - 2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  exit(0);
}

if ( ! defined_func("bsd_byte_ordering") ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);
if (  islocalhost() ) exit(0);


include("raw.inc");
include("sinfp.inc");

port = get_host_open_port();
if ( ! port ) exit(0);
res = sinfp(dport:port);
if ( isnull(res) ) exit(0);
fingerprint = res["fingerprint"];
osname = res["osname"];
confidence = res["confidence"];

set_kb_item(name:"Host/OS/SinFP/Fingerprint", value:fingerprint);

if ( !isnull(osname) )
{
 data = os_name_split(osname);
 if ( data["num"] > 5 ) exit(0);
 set_kb_item(name:"Host/OS/SinFP", value:data["os"]);
 if ( data["type"] )
  set_kb_item(name:"Host/OS/SinFP/Type", value:data["type"]);
 if ( data["num"] > 1 ) confidence -= 11;
 set_kb_item(name:"Host/OS/SinFP/Confidence", value:confidence);
}

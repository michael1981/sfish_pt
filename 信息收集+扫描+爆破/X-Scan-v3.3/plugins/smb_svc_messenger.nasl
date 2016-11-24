#
# (C) Tenable Network Security, Inc.
#

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

include( 'compat.inc' );

if(description)
{
  script_id(10458);
  script_version ("$Revision: 1.11 $");
  script_cve_id("CVE-1999-0630");

  script_name(english:"The messenger service is running");
  script_summary(english:"Checks for the presence of the messenger service");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service allows users to send pop-up messages to each other.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The messenger service is running. This service allows
NT users to send pop-up messages to each other.

This service can be abused by  who can
trick valid users into doing some actions that may
harm their accounts or your network (social
engineering attack)"
  );

  script_set_attribute(
    attribute:'solution',
    value:"Disable this service.

How to disable this service under NT 4 :
    - open the 'Services' control panel
    - select the 'messenger' service, and click 'Stop'
    - click on 'Startup...' and change to radio button of the
      field 'Startup Type' from 'Automatic' to 'Disabled'

Under Windows 2000 :
    - open the 'Administration tools' control panel
    - open the 'Services' item in it
    - double click on the 'messenger' service
    - click on 'stop'
    - change the drop-down menu value from the field 'Startup Type'
      from 'Automatic' to 'Disabled'"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc." );
  script_family(english:"Windows");
  script_dependencie("smb_enum_services.nasl");
  script_require_keys("SMB/svcs");
  exit(0);
}

#
# The script code starts here
#
port = get_kb_item("SMB/transport");
if(!port)port = 139;


services = get_kb_item("SMB/svcs");
if(services)
{
 if("[Messenger]" >< services)security_hole(port);
}

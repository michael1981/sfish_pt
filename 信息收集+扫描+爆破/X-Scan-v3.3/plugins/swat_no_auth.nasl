#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(26926);
  script_version("$Revision: 1.3 $");

  script_name(english:"SWAT Unauthenticated Access (Demo Mode)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server for Samba administration." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SWAT, the Samba Web Administration Tool.

The remote SWAT server appears to be running in demo mode.
In demo mode, authentication is disabled and anyone can use SWAT to 
modify Samba's configuration file. Demo mode should not be used on a 
production server." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/docs/man/Samba-HOWTO-Collection/SWAT.html" );
 script_set_attribute(attribute:"solution", value:
"Either disable SWAT or limit access to authorized users and ensure that
it is set up with stunnel to encrypt network traffic." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_summary(english:"Detects a SWAT Server in demo mode");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("swat_detect.nasl");
  script_require_ports("Services/swat", "Services/www", 901);
  exit(0);
}


port = get_kb_item("SWAT/no_auth");
if (!isnull(port))
  security_hole(port);

#
# (C) Tenable Network Security
#


include("compat.inc");


if (description)
{
 script_id(12098);
 script_cve_id("CVE-2004-0148");
 script_bugtraq_id(9832);
 script_xref(name:"RHSA", value:"RHSA-2003:307-01");
 script_xref(name:"OSVDB", value:"4160");
 script_xref(name:"Secunia", value:"20168");
 script_xref(name:"Secunia", value:"11055");
 script_version("$Revision: 1.8 $");

 script_name(english:"WU-FTPD restricted-gid Directory Access Restriction Bypass");
 script_summary(english:"Checks the remote Wu-ftpd version");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote FTP server has an access restriction bypass vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running wu-ftpd 2.6.2 or older.\n\n",
     "There is a bug in this version which may allow an attacker to bypass the\n",
     "'restricted-gid' feature and gain unauthorized access to otherwise restricted\n",
     "directories.\n\n",
     "*** Nessus solely relied on the banner of the remote FTP server, so this might\n",
     "*** be a false positive."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vendor/2004-q1/0073.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");
include("backport.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_backport_banner(banner:get_ftp_banner(port:port));
if ( ! banner ) exit(0);

if(egrep(pattern:"^220.*wu-((1\..*)|2\.([0-5]\..*|6\.[0-2]))", string:banner, icase:TRUE))
        security_hole(port);

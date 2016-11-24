#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15819);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1067");
 script_bugtraq_id(11729, 11738);
 script_xref(name:"OSVDB", value:"12098");
 script_xref(name:"OSVDB", value:"12097");
 script_xref(name:"OSVDB", value:"12096");
 script_xref(name:"OSVDB", value:"12348");
  
 script_name(english:"Cyrus IMAP Server < 2.2.10 Multiple Remote Overflows");
 script_summary(english:"Checks for a Cyrus IMAPD version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote Cyrus IMAPD server is vulnerable\n",
     "to one pre-authentication buffer overflow, as well as three post-\n",
     "authentication buffer overflows.  A remote attacker could exploit\n",
     "these issues to crash the server, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Cyrus IMAPD 2.2.10 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("cyrus_imap_prelogin_overflow.nasl");
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}


include("global_settings.inc");


# nb: banner checks of open-source software are prone to false-positives
#     so we only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/imap");
if(!port) port = 143;

kb = get_kb_item("imap/" + port + "/Cyrus");
if ( ! kb ) exit(0);
if ( egrep(pattern:"^(1\..*|2\.([0-1]\..*|2\.[0-9][^0-9].*))", string:kb ))
	security_hole ( port );

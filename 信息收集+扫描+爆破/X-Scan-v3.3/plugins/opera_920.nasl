#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25036);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1114", "CVE-2007-1115", "CVE-2007-1563");
  script_bugtraq_id(22701, 23089);
  script_xref(name:"OSVDB", value:"32118");
  script_xref(name:"OSVDB", value:"43499");

  script_name(english:"Opera < 9.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser which is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly may allow
a remote attacker to bypass XSS filters because it renders a web page
without a defined charset with the charset of the parent page. 

In addition, its FTP implementation can be leveraged by remote
attackers to force the client to connect to arbitrary servers via FTP
PASV responses." );
 script_set_attribute(attribute:"see_also", value:"http://bindshell.net/papers/ftppasv" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_032007.142.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/855/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.20 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^9\.[01][0-9]($|[^0-9])")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}

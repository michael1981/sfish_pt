#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40827);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(36202);
  
  script_xref(name:"Secunia", value:"36414");
  script_name(english:"Opera < 10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis",value:
"The remote host contains a web browser that is affected by multiple
issues."
  );
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.0 and thus reportedly affected by multiple issues :

  - The collapsed Address bar can in some cases temporarily
    show the previous domain of the present site. (930)

  - Certificates which use a wild card immediately before
    the top level domain, or nulls in the domain name, may
    pass validation checks in Opera. Sites using such
    certificates may then incorrectly be presented as
    secure. (934)

  - Some Unicode characters are treated incorrectly which
    might cause international domain names that use them to
    be shown in the wrong format. Showing these addresses in
    Unicode instead of punycode could allow for limited
    address spoofing. (932)

  - Opera does not check the revocation status for
    intermediate certificates not served by the server. If
    the intermediate is revoked, this might not impact the
    security rating in Opera, and the site might be shown as
    secure. (929)"
  );

  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/929/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/930/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/932/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/934/"
  );
  script_set_attribute(attribute:"solution", 
    value:"Upgrade to Opera 10.0 or later."
  );
  script_set_attribute(attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
  );
  script_set_attribute(attribute:"vuln_publication_date",
    value:"2009/09/01"
  );
  script_set_attribute(attribute:"patch_publication_date",
    value:"2009/09/01"
  );
  script_set_attribute(attribute:"plugin_publication_date",
    value:"2009/09/01"
  );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "Opera version info was not found in the registry.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 10)
{
  if (report_verbosity > 0 && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
}
exit(0, "The installed version of Opera is not affected");

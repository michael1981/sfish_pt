#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
  script_id(38153);
  script_version("$Revision: 1.4 $");

  script_name(english: "Summary of Missing Microsoft Patches");
  script_summary(english:"Displays the list of missing MSFT patches");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is missing several Microsoft Security Patches\n"
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
 "This plugin summarizes the list of Microsoft Security Patches which 
have not been installed on the remote host.

You should review and apply them to be up-to-date."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string("Run Windows Update on the remote host, or use a patch management solution")
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 

  exit(0);
}

if (isnull(get_kb_list("SMB/Registry/Enumerated"))) 
  exit(0, "Could not enumerate the registry.");

list = get_kb_list("SMB/Missing/*");
if ( isnull(list) ) exit(0, "No missing patches were found in the KB for this host.");

report = 'The patches for the following bulletins are missing on the remote host :\n\n';
foreach patch (sort(keys(list))) 
{
 patch -= "SMB/Missing/";
 report += ' - ' + patch + ' ( http://www.microsoft.com/technet/security/bulletin/' + tolower(patch) + '.mspx )\n';
}

security_note(port:0, extra:report);

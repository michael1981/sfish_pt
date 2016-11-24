#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35298);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0022");
  script_bugtraq_id(33118);
  script_xref(name:"Secunia", value:"33379");

  script_name(english:"Samba 3.2.0 - 3.2.6 Unauthorized Access");
  script_summary(english:"Checks version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by an unauthorized access
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is between 3.2.0 and 3.2.6 inclusive.  Such versions reportedly
allow an authenticated remote user to gain access to the root
filesystem, subject to his or her privileges, by making a request for
a share called '' (empty string) from a version of smbclient prior to
3.0.28.  Successful exploitation of this issue requires 'registry
shares' to be enabled, which is not enabled by default. 

Note that Nessus has not actually tried to exploit this issue or to
determine if 'registry shares' is enabled or if the fix has been
applied." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2009-0022.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.2.7.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.2.7 or later or apply the appropriate patch
referenced in the project's advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager");

  exit(0);
}


include("global_settings.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman) || "Samba " >!< lanman) exit(0);

if (ereg(pattern:"Samba 3\.2\.[0-6][^0-9]*$", string:lanman, icase:TRUE))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Samba server appears to be :\n",
      "\n",
      "  ", lanman, "\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}

#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25756);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-3970", "CVE-2007-3971", "CVE-2007-3972");
  script_bugtraq_id(24988);
  script_xref(name:"OSVDB", value:"37976");
  script_xref(name:"OSVDB", value:"37977");
  script_xref(name:"OSVDB", value:"37978");

  script_name(english:"NOD32 Run-Time Decompressors Multiple Vulnerabilities");
  script_summary(english:"Checks version of NOD32 virus signature database"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of NOD32 installed on the remote host reportedly contains
several problems with its run-time decompressors involving processing
of '.CAB' files as well as 'ASPACK'- and 'FSB'-packed files.  If a
remote attacker can cause a malicious file to be scanned by the
affected application, he may be able to leverage these issues to crash
the affected application or to execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0421.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0422.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0423.html" );
 script_set_attribute(attribute:"see_also", value:"http://eset.com/support/updates.php (look for 'v.2289 (20070716)')" );
 script_set_attribute(attribute:"solution", value:
"Run NOD32's Update feature an ensure the version of the virus
signature database is at least v.2289." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("nod32_installed.nasl");
  script_require_keys("Antivirus/NOD32/installed", "Antivirus/NOD32/sigs");

  exit(0);
}


# Get the signature database update for the target.
sigs = get_kb_item("Antivirus/NOD32/sigs");
if (!sigs) exit(0);

matches = eregmatch(pattern:"^([0-9]+) \(([0-9]+)\)", string:sigs);
if (!isnull(matches)) update = int(matches[1]);
else exit(0);


# There's a problem if the update is before 2289.
if (update < 2289)
{
  report = string(
    "\n",
    "The current virus signature database update on the remote is : \n",
    "\n",
    "  ", sigs, "\n"
  );
  security_warning(port:get_kb_item("SMB/transport"), extra:report);
}

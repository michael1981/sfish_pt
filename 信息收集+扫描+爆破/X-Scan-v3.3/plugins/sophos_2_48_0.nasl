#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25933);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-4577", "CVE-2007-4578");
  script_bugtraq_id(25428);
  script_xref(name:"OSVDB", value:"37986");
  script_xref(name:"OSVDB", value:"37987");

  script_name(english:"Sophos Anti-Virus UPX and BZIP File Multiple Vulnerabilities");
  script_summary(english:"Checks version of Sophos engine"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sophos Anti-Virus installed on the remote host
reportedly contains several problems involving the processing of 'UPX'
and 'BZIP' files.  If a remote attacker can cause a malicious file to
be scanned by the affected application, he may be able to leverage
these issues to crash the affected application, fill up space on the
disk volume used for Engine temporary files, or possibly even execute
arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-08/0408.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-08/0416.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-09/0023.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/support/knowledgebase/article/28407.html" );
 script_set_attribute(attribute:"solution", value:
"Update to Sophos Anti-Virus engine version 2.48.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/eng_ver");

  exit(0);
}


# Get the signature database update for the target.
engine = get_kb_item("Antivirus/Sophos/eng_ver");
if (!engine) exit(0);

ver = split(engine, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("2.48.0", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    # nb: Sophos doesn't report the last part in its advisory.
    ver = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "\n",
      "The current engine version on the remote is ", ver, ".\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
    break;
  }
  else if (ver[i] > fix[i])
    break;

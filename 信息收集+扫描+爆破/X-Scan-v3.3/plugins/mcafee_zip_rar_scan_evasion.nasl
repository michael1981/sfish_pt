#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38654);
  script_version("$Revision: 1.2 $");
  
  script_cve_id("CVE-2009-1348");
  script_bugtraq_id(34780);
  script_xref(name:"OSVDB", value:"54177");

  script_name(english:"McAfee Anti-Virus ZIP/RAR File Scan Evasion");
  script_summary(english:"Checks DAT version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host has an anti-virus software that is affected by a scan
evasion vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host has an anti-virus product from McAfee installed. The
DAT file version of the installed anti-virus product is older than 
5600, and hence it may be possible for certain ZIP/RAR files to evade
detection from the scanning engine." );
  script_set_attribute(attribute:"see_also", value:"http://blog.zoller.lu/2009/04/mcafee-multiple-bypassesevasions-ziprar.html" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-04/0310.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24888ca6 (McAfee Advisory)" );
  script_set_attribute(attribute:"solution", value:
"Update DAT files to version 5600 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed", "Antivirus/McAfee/dat_version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");

dat = get_kb_item("Antivirus/McAfee/dat_version");
if (!dat) exit(0);

if (dat < 5600)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = string(
     "\n",
     "DAT file version ", dat, " is installed on the remote system.\n"
     );
     security_warning(port:port, extra:report);
  }
  else security_warning(port);
}

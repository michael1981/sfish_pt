#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(24681);
  script_bugtraq_id(22449);
  script_xref(name:"OSVDB", value:"33038");
  script_cve_id("CVE-2007-0851");
  script_version("$Revision: 1.7 $");

  script_name(english:"Trend Micro UPX file parsing flaw detection");
  script_summary(english:"Checks if Trend Micro Antivirus virus pattern file is vulnerable"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Trend Antivirus, a commercial anti-virus
software package for Windows.  The scan engine of the remote antivirus
is vulnerable to a UPX file parsing flaw which could potentially allow
an attacker to crash the scan engine or execute arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Upgrade virus pattern file to 4.245.00 or higher." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf2ff5c" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/276432" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bbc4482" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");

pattern_ver = get_kb_item("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
good_pattern_ver = 424500;

# - check if virus pattern file is vulnerable?

trouble = 0;
if (!isnull(pattern_ver))
{
    if ( int(pattern_ver) < int(good_pattern_ver))
    {
      info += 'The virus pattern file ' + pattern_ver + ' on the remote host is vulnerable to the above flaw,' +
              ' please upgrade to ' + good_pattern_ver + ' or higher.\n';
      trouble++;
    }
}

if (trouble)
{
  report = string(
    "\n",
    info
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}

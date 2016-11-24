#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32476);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-1105");
  script_bugtraq_id(29404);
  script_xref(name:"Secunia", value:"30228");
  script_xref(name:"OSVDB", value:"45657");

  script_name(english:"Samba < 3.0.30 receive_smb_raw Function Remote Buffer Overflow");
  script_summary(english:"Checks version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is reportedly affected by a boundary error in 'nmbd' within the
'receive_smb_raw' function in 'lib/util_sock.c' when parsing SMB
packets received in a client context.  By sending specially-crafted
packets to an 'nmbd' server configured as a local or domain master
browser, an attacker can leverage this issue to produce a heap-based
buffer overflow and execute arbitrary code with system privileges. 

Note that Nessus has not actually tried to exploit this issue, verify
the remote 'nmbd' server's configuration, or determine if the fix has
been applied." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-20/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2008-1105.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0354.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.0.30 or later or apply the patch referenced
in the project's advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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

if (ereg(pattern:"Samba 3\.0\.([0-9]|[12][0-9])[^0-9]*$", string:lanman, icase:TRUE))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Samba server appears to be :\n",
      "\n",
      "  ", lanman, "\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41626);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36439);
  script_xref(name:"OSVDB", value:"58215");
  script_xref(name:"OSVDB", value:"58216");
  script_xref(name:"OSVDB", value:"58217");
  script_xref(name:"Secunia", value:"36762");

  script_name(english:"VLC Media Player < 1.0.2 Multiple Remote Buffer Overflows");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains an application that is affected by\n",
      "multiple remote buffer overflow vulnerabilities."
    )
  );

  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of VLC media player installed on the remote host is\n",
      "earlier than 1.0.2.  Such versions are vulnerable to a stack overflow\n",
      "when parsing MP4, ASF, or AVI files with an overly deep box structure.\n",
      "If an attacker can trick a user into opening a specially crafted MP4,\n",
      "ASF, or AVI file with the affected application, he may be able to\n",
      "execute arbitrary code subject to the user's privileges."
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa0901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78382b17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c3b223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82f87f14"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.0.2 or later."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/25"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("global_settings.inc");

ver = get_kb_item("SMB/VLC/Version");
if (isnull(ver)) exit(1, "The 'SMB/VLC/Version' KB key is missing.");

if (tolower(ver) =~ "^(0\.|1\.0\.[01]($|[^0-9]))")
{
  if (report_verbosity > 0)
  { 
    report = string(
      "\n",
      "VLC Media Player version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+ver+" is installed.");

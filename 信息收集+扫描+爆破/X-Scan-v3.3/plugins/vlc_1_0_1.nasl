#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40466);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(35821);
  script_xref(name:"OSVDB", value:"56604");
  script_xref(name:"Secunia", value:"36037");

  script_name(english:"VLC Media Player < 1.0.1 real_get_rdt_chunk() Function Overflow");
  script_summary(english:"Checks version of VLC");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains an application that is affected by a\n",
      "buffer overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of VLC media player installed on the remote host is \n",
      "earlier than 1.0.1.  Such versions contain an integer underflow \n",
      "involving the integer 'size' in the 'real_get_rdt_chunk_header()'\n",
      "function that can be triggered when reading Real Data Transport (RDT)\n",
      "chunk headers.  This 'size' variable is used before the underflow to\n",
      "allocate storage on the heap and then after it to read an excessive \n",
      "amount of data from the network via the 'rtsp_read_data()' function,\n",
      "resulting in a buffer overflow.  If an attacker can trick a user into\n",
      "opening a specially crafted RTSP stream with the affected application,\n",
      "he may be able to execute arbitrary code subject to the user's\n",
      "privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-07/0198.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://wiki.videolan.org/Changelog/1.0.1#Access"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to VLC Media Player version 1.0.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/28"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/01"
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
if (isnull(ver)) exit(1, "No version info found in the KB.");

if (tolower(ver) =~ "^(0\.|1\.0\.0($|[^0-9]))")
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
else exit(0, "No vulnerable instances were found.");

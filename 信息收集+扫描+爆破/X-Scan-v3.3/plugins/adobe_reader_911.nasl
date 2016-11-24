#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38746);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-1492");
  script_bugtraq_id(34736);
  script_xref(name:"OSVDB", value:"54130");
  script_xref(name:"Secunia", value:"34924");

  script_name(english:"Adobe Reader getAnnots() JavaScript Method PDF Handling Memory Corruption");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The PDF file viewer on the remote Windows host is affected by a memory\n",
      "corruption vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Adobe Reader installed on the remote host is earlier\n",
      "than 9.1.1 / 8.1.5 / 7.1.2.  Such versions reportedly fail to validate\n",
      "input from a specially crafted PDF file before passing it to the\n",
      "JavaScript method 'getAnnots()' leading to memory corruption and\n",
      "possibly arbitrary code execution."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/advisories/apsa09-02.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.kb.cert.org/vuls/id/970180"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb09-06.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Adobe Reader 9.1.1 / 8.1.5 / 7.1.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Acroread/Version");
if (
  ver && 
  (
    ver =~ "^[0-6]\." ||
    ver =~ "^7\.(0\.|1\.[01]($|[^0-9]))" ||
    ver =~ "^8\.(0\.|1\.[0-4]($|[^0-9]))" ||
    ver =~ "^9\.(0\.|1\.0($|[^0-9]))"
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote version of Adobe Reader is ", ver, ".\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}

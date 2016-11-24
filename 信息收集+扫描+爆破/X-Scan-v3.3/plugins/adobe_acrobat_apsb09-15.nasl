#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');
if (NASL_LEVEL < 3000) exit(0);

if (description)
{
  script_id(42119);
  script_version('$Revision: 1.3 $');

  script_cve_id("CVE-2007-0048", "CVE-2007-0045", "CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981",
                "CVE-2009-2982", "CVE-2009-2983", "CVE-2009-2984", "CVE-2009-2985", "CVE-2009-2986",
                "CVE-2009-2987", "CVE-2009-2988", "CVE-2009-2989", "CVE-2009-2990", "CVE-2009-2991",
                "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994", "CVE-2009-2995", "CVE-2009-2996",
                "CVE-2009-2997", "CVE-2009-2998", "CVE-2009-3431", "CVE-2009-3458", "CVE-2009-3459",
                "CVE-2009-3460", "CVE-2009-3461");
  script_bugtraq_id(36600, 36664, 36665, 36667, 36668, 36669, 36671, 36677, 36678, 36680,
                    36682, 36684, 36686, 36687, 36688, 36689, 36690, 36691, 36692, 36693,
                    36694, 36695, 36697);
  script_xref(name:"OSVDB", value:"31046");
  script_xref(name:"OSVDB", value:"31596");
  script_xref(name:"OSVDB", value:"58415");
  script_xref(name:"OSVDB", value:"58729");
  script_xref(name:"OSVDB", value:"58906");
  script_xref(name:"OSVDB", value:"58907");
  script_xref(name:"OSVDB", value:"58908");
  script_xref(name:"OSVDB", value:"58909");
  script_xref(name:"OSVDB", value:"58910");
  script_xref(name:"OSVDB", value:"58911");
  script_xref(name:"OSVDB", value:"58912");
  script_xref(name:"OSVDB", value:"58913");
  script_xref(name:"OSVDB", value:"58914");
  script_xref(name:"OSVDB", value:"58915");
  script_xref(name:"OSVDB", value:"58916");
  script_xref(name:"OSVDB", value:"58917");
  script_xref(name:"OSVDB", value:"58918");
  script_xref(name:"OSVDB", value:"58919");
  script_xref(name:"OSVDB", value:"58920");
  script_xref(name:"OSVDB", value:"58921");
  script_xref(name:"OSVDB", value:"58922");
  script_xref(name:"OSVDB", value:"58923");
  script_xref(name:"OSVDB", value:"58924");
  script_xref(name:"OSVDB", value:"58925");
  script_xref(name:"OSVDB", value:"58926");
  script_xref(name:"OSVDB", value:"58927");
  script_xref(name:"OSVDB", value:"58928");
  script_xref(name:"OSVDB", value:"58929");
  script_xref(name:"Secunia", value:"36983");

  script_name(english:"Adobe Acrobat < 9.2 / 8.1.7 / 7.1.4  Multiple Vulnerabilities (APSB09-15)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The version of Adobe Acrobat on the remote Windows host is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Adobe Acrobat installed on the remote host is earlier\n",
      "than 9.2 / 8.1.7 / 7.1.4. Such versions are reportedly affected by\n",
      "multiple vulnerabilities :\n",
      "\n",
      "  - A heap overflow vulnerability. (CVE-2009-3459)\n",
      "\n",
      "  - A memory corruption issue. (CVE-2009-2985)\n",
      "\n",
      "  - Multiple heap overflow vulnerabilities. (CVE-2009-2986)\n",
      "\n",
      "  - An invalid array index issue that could lead to code\n",
      "    execution. (CVE-2009-2990)\n",
      "\n",
      "  - Multiple input validation vulnerabilities that could\n",
      "    lead to code execution. (CVE-2009-2993)\n",
      "\n",
      "  - A buffer overflow issue. (CVE-2009-2994)\n",
      "\n",
      "  - A heap overflow vulnerability. (CVE-2009-2997)\n",
      "\n",
      "  - An input validation issue that could lead to code\n",
      "    execution. (CVE-2009-2998)\n",
      "\n",
      "  - An input validation issue that could lead to code\n",
      "    execution. (CVE-2009-3458)\n",
      "\n",
      "  - A memory corruption issue. (CVE-2009-3460)\n",
      "\n",
      "  - An issue that could allow a malicious user to bypass\n",
      "    file extension security controls. (CVE-2009-3461)\n",
      "\n",
      "  - An integer overflow vulnerability. (CVE-2009-2989)\n",
      "\n",
      "  - A memory corruption issue that leads to a denial of\n",
      "    service. (CVE-2009-2983)\n",
      "\n",
      "  - An integer overflow that leads to a denial of service.\n",
      "    (CVE-2009-2980)\n",
      "\n",
      "  - A memory corruption issue that leads to a denial of\n",
      "    service. (CVE-2009-2996)\n",
      "\n",
      "  - An image decoder issue that leads to a denial of service.\n",
      "    (CVE-2009-2984)\n",
      "\n",
      "  - An input validation issue that could lead to a bypass\n",
      "    of Trust Manager restrictions. (CVE-2009-2981)\n",
      "\n",
      "  - A certificate is used that, if compromised, could be used\n",
      "    in a social engineering attack. (CVE-2009-2982)\n",
      "\n",
      "  - A stack overflow issue that could lead to a denial of\n",
      "    service. (CVE-2009-3431)\n",
      "\n",
      "  - A XMP-XML entity expansion issue that could lead to a\n",
      "    denial of service attack. (CVE-2009-2979)\n",
      "\n",
      "  - A remote denial of service issue in the ActiveX control.\n",
      "    (CVE-2009-2987)\n",
      "\n",
      "  - An input validation issue. (CVE-2009-2988)\n",
      "\n",
      "  - An input validation issue specific to the ActiveX \n",
      "    control. (CVE-2009-2992)\n",
      "\n",
      "  - A cross-site scripting issue when the browser plugin in\n",
      "    used with Google Chrome and Opera browsers. \n",
      "    (CVE-2007-0048, CVE-2007-0045)\n",
      "\n"
    )
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.adobe.com/support/security/bulletins/apsb09-15.html'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to Adobe Acrobat 9.2 / 8.1.7 / 7.1.4 or later.'
  );
  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C'
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2009 Tenable Network Security, Inc.');
  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}

#

include('global_settings.inc');

version = get_kb_item('SMB/Acrobat/Version');
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if  ( 
  ver[0] < 7 ||
  (
    ver[0] == 7 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 4)
    )
  ) ||
  (
    ver[0] == 8 &&
    (
      ver[1] < 1 ||
      (ver[1] == 1 && ver[2] < 7)
    )
  ) ||
  (
    ver[0] == 9 &&  ver[1] < 2
  )
)
{
  version_ui = get_kb_item('SMB/Acrobat/Version_UI');
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report = string(
      '\n',
      '  Product           : Adobe Acrobat\n',
      '  Path              : ', path, '\n',
      '  Installed version : ', version_ui, '\n',
      '  Fix               : 9.2 / 8.1.7 / 7.1.4\n'
    );
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version+" is installed.");

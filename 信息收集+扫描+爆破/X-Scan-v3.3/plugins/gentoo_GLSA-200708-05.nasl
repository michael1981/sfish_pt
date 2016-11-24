# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(25870);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-05");
 script_cve_id("CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-05
(GD: Multiple vulnerabilities)


    Xavier Roche discovered an infinite loop in the gdPngReadData()
    function when processing a truncated PNG file (CVE-2007-2756). An
    integer overflow has been discovered in the gdImageCreateTrueColor()
    function (CVE-2007-3472). An error has been discovered in the function
    gdImageCreateXbm() function (CVE-2007-3473). Unspecified
    vulnerabilities have been discovered in the GIF reader (CVE-2007-3474).
    An error has been discovered when processing a GIF image that has no
    global color map (CVE-2007-3475). An array index error has been
    discovered in the file gd_gif_in.c when processing images with an
    invalid color index (CVE-2007-3476). An error has been discovered in
    the imagearc() and imagefilledarc() functions when processing overly
    large angle values (CVE-2007-3477). A race condition has been
    discovered in the gdImageStringFTEx() function (CVE-2007-3478).
  
Impact

    A remote attacker could exploit one of these vulnerabilities to cause a
    Denial of Service or possibly execute arbitrary code with the
    privileges of the user running GD.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gd-2.0.35"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2756');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3472');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3473');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3474');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3475');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3476');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3477');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3478');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-05] GD: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GD: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/gd", unaffected: make_list("ge 2.0.35"), vulnerable: make_list("lt 2.0.35")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

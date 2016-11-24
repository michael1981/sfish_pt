# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-17.xml
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
 script_id(29814);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-17");
 script_cve_id("CVE-2007-6354", "CVE-2007-6355", "CVE-2007-6356");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-17
(exiftags: Multiple vulnerabilities)


    Meder Kydyraliev (Google Security) discovered that Exif metadata is not
    properly sanitized before being processed, resulting in illegal memory
    access in the postprop() and other functions (CVE-2007-6354). He also
    discovered integer overflow vulnerabilities in the parsetag() and other
    functions (CVE-2007-6355) and an infinite recursion in the readifds()
    function caused by recursive IFD references (CVE-2007-6356).
  
Impact

    An attacker could entice the user of an application making use of
    exiftags or an application included in exiftags to load an image file
    with specially crafted Exif tags, possibly resulting in the execution
    of arbitrary code with the privileges of the user running the
    application or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All exiftags users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/exiftags-1.01"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6354');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6355');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6356');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-17] exiftags: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'exiftags: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/exiftags", unaffected: make_list("ge 1.01"), vulnerable: make_list("lt 1.01")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

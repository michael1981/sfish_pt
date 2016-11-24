# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-12.xml
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
 script_id(40959);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-12");
 script_cve_id("CVE-2009-3050");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-12
(HTMLDOC: User-assisted execution of arbitrary code)


    ANTHRAX666 reported an insecure call to the sscanf() function in the
    set_page_size() function in htmldoc/util.cxx. Nico Golde of the Debian
    Security Team found two more insecure calls in the write_type1()
    function in htmldoc/ps-pdf.cxx and the htmlLoadFontWidths() function in
    htmldoc/htmllib.cxx.
  
Impact

    A remote attacker could entice a user to process a specially crafted
    HTML file using htmldoc, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application.
    NOTE: Additional vectors via specially crafted AFM font metric files do
    not cross trust boundaries, as the files can only be modified by
    privileged users.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All HTMLDOC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =app-text/htmldoc-1.8.27-r1
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3050');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-12] HTMLDOC: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HTMLDOC: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/htmldoc", unaffected: make_list("ge 1.8.27-r1"), vulnerable: make_list("lt 1.8.27-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

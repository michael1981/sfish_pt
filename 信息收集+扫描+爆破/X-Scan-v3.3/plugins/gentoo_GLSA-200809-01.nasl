# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-01.xml
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
 script_id(34090);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-01");
 script_cve_id("CVE-2008-3533");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-01
(yelp: User-assisted execution of arbitrary code)


    Aaron Grattafiori reported a format string vulnerability in the
    window_error() function in yelp-window.c.
  
Impact

    A remote attacker can entice a user to open specially crafted "man:" or
    "ghelp:" URIs in yelp, or an application using yelp such as Firefox or
    Evolution, and execute arbitrary code with the privileges of that user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All yelp users running GNOME 2.22 should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-extra/yelp-2.22.1-r2"
    All yelp users running GNOME 2.20 should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-extra/yelp-2.20.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3533');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-01] yelp: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'yelp: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "gnome-extra/yelp", unaffected: make_list("ge 2.22.1-r2", "rge 2.20.0-r1"), vulnerable: make_list("lt 2.22.1-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

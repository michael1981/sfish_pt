# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-03.xml
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
 script_id(25453);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200706-03");
 script_cve_id("CVE-2007-2027");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-03
(ELinks: User-assisted execution of arbitrary code)


    Arnaud Giersch discovered that the "add_filename_to_string()" function
    in file intl/gettext/loadmsgcat.c uses an untrusted relative path,
    allowing for a format string attack with a malicious .po file.
  
Impact

    A local attacker could entice a user to run ELinks in a specially
    crafted directory environment containing a malicious ".po" file,
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running ELinks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ELinks users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/elinks-0.11.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2027');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-03] ELinks: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ELinks: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/elinks", unaffected: make_list("ge 0.11.2-r1"), vulnerable: make_list("lt 0.11.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

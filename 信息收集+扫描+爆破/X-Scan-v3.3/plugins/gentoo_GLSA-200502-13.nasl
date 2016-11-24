# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-13.xml
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
 script_id(16450);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-13");
 script_cve_id("CVE-2005-0155", "CVE-2005-0156");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-13
(Perl: Vulnerabilities in perl-suid wrapper)


    perl-suid scripts honor the PERLIO_DEBUG environment variable and
    write to that file with elevated privileges (CAN-2005-0155).
    Furthermore, calling a perl-suid script with a very long path while
    PERLIO_DEBUG is set could trigger a buffer overflow (CAN-2005-0156).
  
Impact

    A local attacker could set the PERLIO_DEBUG environment variable
    and call existing perl-suid scripts, resulting in file overwriting and
    potentially the execution of arbitrary code with root privileges.
  
Workaround

    You are not vulnerable if you do not have the perlsuid USE flag
    set or do not use perl-suid scripts.
  
');
script_set_attribute(attribute:'solution', value: '
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0155');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0156');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-13] Perl: Vulnerabilities in perl-suid wrapper');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: Vulnerabilities in perl-suid wrapper');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.6-r3", "rge 5.8.5-r4", "rge 5.8.4-r3", "rge 5.8.2-r3"), vulnerable: make_list("lt 5.8.6-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

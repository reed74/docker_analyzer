-- 1. Creación de la tabla temporal --

            CREATE TEMPORARY TABLE input_packages (
                product TEXT,
                version TEXT
            ) ON COMMIT DROP;
        

-- 2. Inserción de 140 paquetes únicos --
INSERT INTO input_packages (product, version) VALUES ('libpng12-0', '1.2.50');
INSERT INTO input_packages (product, version) VALUES ('libtinfo5', '5.9');
INSERT INTO input_packages (product, version) VALUES ('e2fsprogs', '1.42.12');
INSERT INTO input_packages (product, version) VALUES ('libbz2-1.0', '1.0.6');
INSERT INTO input_packages (product, version) VALUES ('libssl1.0.0', '1.0.1t');
INSERT INTO input_packages (product, version) VALUES ('coreutils', '8.23');
INSERT INTO input_packages (product, version) VALUES ('libaudit1', '1:2.4');
INSERT INTO input_packages (product, version) VALUES ('libcap2-bin', '1:2.24');
INSERT INTO input_packages (product, version) VALUES ('procps', '2:3.3.9');
INSERT INTO input_packages (product, version) VALUES ('libc6', '2.19');
INSERT INTO input_packages (product, version) VALUES ('init', '1.22');
INSERT INTO input_packages (product, version) VALUES ('libxcb1', '1.10');
INSERT INTO input_packages (product, version) VALUES ('mawk', '1.3.3');
INSERT INTO input_packages (product, version) VALUES ('libapt-pkg4.12', '1.0.9.8.4');
INSERT INTO input_packages (product, version) VALUES ('libjbig0', '2.1');
INSERT INTO input_packages (product, version) VALUES ('acl', '2.2.52');
INSERT INTO input_packages (product, version) VALUES ('sensible-utils', '0.0.9');
INSERT INTO input_packages (product, version) VALUES ('initscripts', '2.88dsf');
INSERT INTO input_packages (product, version) VALUES ('gcc-4.9-base', '4.9.2');
INSERT INTO input_packages (product, version) VALUES ('libgcrypt20', '1.6.3');
INSERT INTO input_packages (product, version) VALUES ('libpam-modules-bin', '1.1.8');
INSERT INTO input_packages (product, version) VALUES ('libselinux1', '2.3');
INSERT INTO input_packages (product, version) VALUES ('debianutils', '4.4');
INSERT INTO input_packages (product, version) VALUES ('ncurses-base', '5.9');
INSERT INTO input_packages (product, version) VALUES ('base-passwd', '3.5.37');
INSERT INTO input_packages (product, version) VALUES ('nginx-module-geoip', '1.10.3');
INSERT INTO input_packages (product, version) VALUES ('fontconfig-config', '2.11.0');
INSERT INTO input_packages (product, version) VALUES ('ncurses-bin', '5.9');
INSERT INTO input_packages (product, version) VALUES ('libaudit-common', '1:2.4');
INSERT INTO input_packages (product, version) VALUES ('apt', '1.0.9.8.4');
INSERT INTO input_packages (product, version) VALUES ('libsemanage-common', '2.3');
INSERT INTO input_packages (product, version) VALUES ('libxdmcp6', '1:1.1.1');
INSERT INTO input_packages (product, version) VALUES ('multiarch-support', '2.19');
INSERT INTO input_packages (product, version) VALUES ('gettext-base', '0.19.3');
INSERT INTO input_packages (product, version) VALUES ('libgd3', '2.1.0');
INSERT INTO input_packages (product, version) VALUES ('libjpeg62-turbo', '1:1.3.1');
INSERT INTO input_packages (product, version) VALUES ('debian-archive-keyring', '2014.3');
INSERT INTO input_packages (product, version) VALUES ('libblkid1', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('systemd', '215');
INSERT INTO input_packages (product, version) VALUES ('passwd', '1:4.2');
INSERT INTO input_packages (product, version) VALUES ('perl', '5.20.2');
INSERT INTO input_packages (product, version) VALUES ('adduser', '3.113');
INSERT INTO input_packages (product, version) VALUES ('libxslt1.1', '1.1.28');
INSERT INTO input_packages (product, version) VALUES ('libx11-data', '2:1.6.2');
INSERT INTO input_packages (product, version) VALUES ('libcap2', '1:2.24');
INSERT INTO input_packages (product, version) VALUES ('libcomerr2', '1.42.12');
INSERT INTO input_packages (product, version) VALUES ('ca-certificates', '20141019');
INSERT INTO input_packages (product, version) VALUES ('iproute2', '3.16.0');
INSERT INTO input_packages (product, version) VALUES ('mount', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('gzip', '1.6');
INSERT INTO input_packages (product, version) VALUES ('findutils', '4.4.2');
INSERT INTO input_packages (product, version) VALUES ('libstdc++6', '4.9.2');
INSERT INTO input_packages (product, version) VALUES ('hostname', '3.15');
INSERT INTO input_packages (product, version) VALUES ('dpkg', '1.17.27');
INSERT INTO input_packages (product, version) VALUES ('perl-modules', '5.20.2');
INSERT INTO input_packages (product, version) VALUES ('gcc-4.8-base', '4.8.4');
INSERT INTO input_packages (product, version) VALUES ('libc-bin', '2.19');
INSERT INTO input_packages (product, version) VALUES ('libpam-modules', '1.1.8');
INSERT INTO input_packages (product, version) VALUES ('sysvinit-utils', '2.88dsf');
INSERT INTO input_packages (product, version) VALUES ('libgcc1', '1:4.9.2');
INSERT INTO input_packages (product, version) VALUES ('libvpx1', '1.3.0');
INSERT INTO input_packages (product, version) VALUES ('nginx-module-image-filter', '1.10.3');
INSERT INTO input_packages (product, version) VALUES ('util-linux', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('libgdbm3', '1.8.3');
INSERT INTO input_packages (product, version) VALUES ('libsepol1', '2.3');
INSERT INTO input_packages (product, version) VALUES ('libmount1', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('nginx-module-njs', '1.10.3.0.0.20160414.1c50334fbea6');
INSERT INTO input_packages (product, version) VALUES ('openssl', '1.0.1t');
INSERT INTO input_packages (product, version) VALUES ('libxpm4', '1:3.5.12');
INSERT INTO input_packages (product, version) VALUES ('ucf', '3.0030');
INSERT INTO input_packages (product, version) VALUES ('libsemanage1', '2.3');
INSERT INTO input_packages (product, version) VALUES ('fonts-dejavu-core', '2.34');
INSERT INTO input_packages (product, version) VALUES ('nginx-module-perl', '1.10.3');
INSERT INTO input_packages (product, version) VALUES ('libxau6', '1:1.0.8');
INSERT INTO input_packages (product, version) VALUES ('perl-base', '5.20.2');
INSERT INTO input_packages (product, version) VALUES ('libfontconfig1', '2.11.0');
INSERT INTO input_packages (product, version) VALUES ('lsb-base', '4.1');
INSERT INTO input_packages (product, version) VALUES ('nginx-module-xslt', '1.10.3');
INSERT INTO input_packages (product, version) VALUES ('libustr-1.0-1', '1.0.4');
INSERT INTO input_packages (product, version) VALUES ('libdb5.3', '5.3.28');
INSERT INTO input_packages (product, version) VALUES ('libtiff5', '4.0.3');
INSERT INTO input_packages (product, version) VALUES ('libusb-0.1-4', '2:0.1.12');
INSERT INTO input_packages (product, version) VALUES ('libxml2', '2.9.1');
INSERT INTO input_packages (product, version) VALUES ('libncursesw5', '5.9');
INSERT INTO input_packages (product, version) VALUES ('libgpg-error0', '1.17');
INSERT INTO input_packages (product, version) VALUES ('gpgv', '1.4.18');
INSERT INTO input_packages (product, version) VALUES ('libncurses5', '5.9');
INSERT INTO input_packages (product, version) VALUES ('dash', '0.5.7');
INSERT INTO input_packages (product, version) VALUES ('sed', '4.2.2');
INSERT INTO input_packages (product, version) VALUES ('libreadline6', '6.3');
INSERT INTO input_packages (product, version) VALUES ('libsystemd0', '215');
INSERT INTO input_packages (product, version) VALUES ('systemd-sysv', '215');
INSERT INTO input_packages (product, version) VALUES ('diffutils', '1:3.3');
INSERT INTO input_packages (product, version) VALUES ('grep', '2.20');
INSERT INTO input_packages (product, version) VALUES ('startpar', '0.59');
INSERT INTO input_packages (product, version) VALUES ('liblocale-gettext-perl', '1.05');
INSERT INTO input_packages (product, version) VALUES ('bash', '4.3');
INSERT INTO input_packages (product, version) VALUES ('libpam0g', '1.1.8');
INSERT INTO input_packages (product, version) VALUES ('inetutils-ping', '2:1.9.2.39.3a460');
INSERT INTO input_packages (product, version) VALUES ('login', '1:4.2');
INSERT INTO input_packages (product, version) VALUES ('libuuid1', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('nginx', '1.10.3');
INSERT INTO input_packages (product, version) VALUES ('libpcre3', '2:8.35');
INSERT INTO input_packages (product, version) VALUES ('libcryptsetup4', '2:1.6.6');
INSERT INTO input_packages (product, version) VALUES ('libexpat1', '2.1.0');
INSERT INTO input_packages (product, version) VALUES ('gnupg', '1.4.18');
INSERT INTO input_packages (product, version) VALUES ('libkmod2', '18');
INSERT INTO input_packages (product, version) VALUES ('libacl1', '2.2.52');
INSERT INTO input_packages (product, version) VALUES ('tar', '1.27.1');
INSERT INTO input_packages (product, version) VALUES ('libtext-wrapi18n-perl', '0.06');
INSERT INTO input_packages (product, version) VALUES ('base-files', '8');
INSERT INTO input_packages (product, version) VALUES ('libx11-6', '2:1.6.2');
INSERT INTO input_packages (product, version) VALUES ('readline-common', '6.3');
INSERT INTO input_packages (product, version) VALUES ('liblzma5', '5.1.1alpha');
INSERT INTO input_packages (product, version) VALUES ('libtext-charwidth-perl', '0.04');
INSERT INTO input_packages (product, version) VALUES ('libss2', '1.42.12');
INSERT INTO input_packages (product, version) VALUES ('libperl5.20', '5.20.2');
INSERT INTO input_packages (product, version) VALUES ('udev', '215');
INSERT INTO input_packages (product, version) VALUES ('dmsetup', '2:1.02.90');
INSERT INTO input_packages (product, version) VALUES ('libattr1', '1:2.4.47');
INSERT INTO input_packages (product, version) VALUES ('debconf', '1.5.56');
INSERT INTO input_packages (product, version) VALUES ('libgeoip1', '1.6.2');
INSERT INTO input_packages (product, version) VALUES ('libasprintf0c2', '0.19.3');
INSERT INTO input_packages (product, version) VALUES ('libdevmapper1.02.1', '2:1.02.90');
INSERT INTO input_packages (product, version) VALUES ('libtext-iconv-perl', '1.7');
INSERT INTO input_packages (product, version) VALUES ('bsdutils', '1:2.25.2');
INSERT INTO input_packages (product, version) VALUES ('libudev1', '215');
INSERT INTO input_packages (product, version) VALUES ('tzdata', '2017a');
INSERT INTO input_packages (product, version) VALUES ('libdebconfclient0', '0.192');
INSERT INTO input_packages (product, version) VALUES ('libprocps3', '2:3.3.9');
INSERT INTO input_packages (product, version) VALUES ('sysv-rc', '2.88dsf');
INSERT INTO input_packages (product, version) VALUES ('zlib1g', '1:1.2.8.dfsg');
INSERT INTO input_packages (product, version) VALUES ('insserv', '1.14.0');
INSERT INTO input_packages (product, version) VALUES ('libslang2', '2.3.0');
INSERT INTO input_packages (product, version) VALUES ('libsmartcols1', '2.25.2');
INSERT INTO input_packages (product, version) VALUES ('libpam-runtime', '1.1.8');
INSERT INTO input_packages (product, version) VALUES ('netbase', '5.3');
INSERT INTO input_packages (product, version) VALUES ('debconf-i18n', '1.5.56');
INSERT INTO input_packages (product, version) VALUES ('e2fslibs', '1.42.12');
INSERT INTO input_packages (product, version) VALUES ('libfreetype6', '2.5.2');

-- 3. Consulta final (JOIN) --

            SELECT 
                p.product, p.version, v.cve_id, v.cvss_v31_severity
            FROM 
                public.vulnerabilities AS v
            JOIN 
                public.vulnerability_product_map AS vpm ON v.id = vpm.vulnerability_id
            JOIN 
                public.products AS p ON vpm.product_id = p.id
            JOIN 
                input_packages AS i 
            ON 
                p.product = i.product 
                AND p.version = i.version;
        

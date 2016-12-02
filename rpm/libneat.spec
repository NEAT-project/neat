Name: libneat
Version: 1.0.0~td114
Release: 1
Summary: NEAT Project
License: BSD
Group: Applications/Internet
URL: https://github.com/NEAT-project/neat
Source: %{name}-%{version}.tar.gz

AutoReqProv: on
BuildRequires: cmake
BuildRequires: jansson-devel
BuildRequires: ldns-devel
BuildRequires: libmnl-devel
BuildRequires: lksctp-tools-devel
BuildRequires: openssl-devel
BuildRequires: libuv-devel
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description
 The NEAT project wants to achieve a complete redesign of the way in which
 Internet applications interact with the network. Our goal is to allow network
 “services” offered to applications – such as reliability, low-delay
 communication or security – to be dynamically tailored based on application
 demands, current network conditions, hardware capabilities or local policies,
 and also to support the integration of new network functionality in an
 evolutionary fashion, without applications having to be rewritten. This
 architectural change will make the Internet truly “enhanceable”, by allowing
 applications to seamlessly and more easily take advantage of new network
 features as they evolve.


%package devel
Summary: NEAT (Development Files)
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
 The NEAT project wants to achieve a complete redesign of the way in which
 Internet applications interact with the network. Our goal is to allow network
 “services” offered to applications – such as reliability, low-delay
 communication or security – to be dynamically tailored based on application
 demands, current network conditions, hardware capabilities or local policies,
 and also to support the integration of new network functionality in an
 evolutionary fashion, without applications having to be rewritten. This
 architectural change will make the Internet truly “enhanceable”, by allowing
 applications to seamlessly and more easily take advantage of new network
 features as they evolve.
 This package contains the built examples for the NEAT Core API.


%package examples
Summary: NEAT (Examples)
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}
Requires: %{name}-docs
Requires: chrpath

%description examples
 The NEAT project wants to achieve a complete redesign of the way in which
 Internet applications interact with the network. Our goal is to allow network
 “services” offered to applications – such as reliability, low-delay
 communication or security – to be dynamically tailored based on application
 demands, current network conditions, hardware capabilities or local policies,
 and also to support the integration of new network functionality in an
 evolutionary fashion, without applications having to be rewritten. This
 architectural change will make the Internet truly “enhanceable”, by allowing
 applications to seamlessly and more easily take advantage of new network
 features as they evolve.
 This package contains the built examples for the NEAT Core API.


%prep
%setup -q

%build
%cmake -DCMAKE_INSTALL_PREFIX=/usr .
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

#%clean
#rm -rf "$RPM_BUILD_ROOT"


%files
%defattr(-,root,root,-)
/usr/lib/libneat.so*

%files devel
/usr/include/neat/neat.h
/usr/include/neat/neat_linux.h
/usr/include/neat/neat_queue.h
/usr/lib//libneat*.a
/usr/lib/libneat*.so

%files examples
/usr/lib/libneat/client
/usr/lib/libneat/client_http_get
/usr/lib/libneat/client_https_get
/usr/lib/libneat/http_client_multihomed
/usr/lib/libneat/peer
/usr/lib/libneat/server_chargen
/usr/lib/libneat/server_daytime
/usr/lib/libneat/server_discard
/usr/lib/libneat/server_echo
/usr/lib/libneat/tneat

%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release

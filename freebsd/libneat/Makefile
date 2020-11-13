# Created by: Thomas Dreibholz <dreibh@iem.uni-due.de>
# $FreeBSD$

PORTNAME=	libneat
PORTVERSION=	1.0.2~td3
CATEGORIES=	net
MASTER_SITES=	https://packages.nntb.no/software/libneat/

MAINTAINER=	dreibh@iem.uni-due.de
COMMENT=	NEAT Project

LICENSE=	BSD
# LICENSE_FILE=	${WRKSRC}/COPYING

LIB_DEPENDS=    libjansson.so:devel/jansson \
		libldns.so:dns/ldns \
		libuv.so:devel/libuv

USES=		cmake ssl
USE_LDCONFIG=	yes

CMAKE_ARGS+=    -DSOCKET_API=1 -DUSRSCTP_SUPPORT=0 -DWEBRTC_SUPPORT=0 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1

PLIST_SUB=      VERSION=${PORTVERSION}

.include <bsd.port.mk>

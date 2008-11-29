/* mtp3io.h - MTP transport over mtp3d sockets interface
 * Author: Anders Baekgaard <ab@dicea.dk>
 * This work is included with chan_ss7, see copyright below.
 */

/*
 * This file is part of chan_ss7.
 *
 * chan_ss7 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * chan_ss7 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with chan_ss7; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


#define MTP3_SOCKETTYPE SOCK_STREAM
#define MTP3_IPPROTO IPPROTO_TCP
//define MTP3_SOCKETTYPE SOCK_SEQPACKET
//define MTP3_IPPROTO IPPROTO_SCTP


int mtp3_setup_socket(int port, int schannel);
int mtp3_connect_socket(const char* host, const char* port);
int mtp3_send(int s, const unsigned char* buff, unsigned int len);
void mtp3_reply(int s, const unsigned char* buff, unsigned int len, const struct sockaddr* to, socklen_t tolen);
int mtp3_register_isup(int s, int linkix);
int mtp3_register_sccp(int s, int subsystem, int linkix);


import subprocess
import sys

import subprocess

def install(name):
    subprocess.call(['pip', 'install', name])
    
# install('dpkt')
# install('pandas')

import logging
import math
import sys

import dpkt
import pandas as pd

log = logging.getLogger(__name__)


def avtpPacketParserforSpecificStreamID(src, dest, minAVTPtimestampDifference,
									  maxAVTPtimestampDifference, streamID):
	''' Extracts AVTP packet information of specified stream id
		from a pcap capture file and stores them in a csv format file
		And Calculates AVTP timestamp difference between 2 consecutive AVTP packets
	Args:
		src(string): Source pcap file path
		dest(string): Destination csv file path
		minAVTPtimestampDifference(int): Minimum allowable AVTP/CRF Timestamp difference
		maxAVTPtimestampDifference(int): Maximyum allowable AVTP/CRF Timestamp difference
		streamID (string) : stream id
	'''
	with open(src, 'rb') as f:
		pcap = dpkt.pcap.Reader(f)
		print("Parsing tcpdump: {}".format(src))

		with open(dest, 'w') as foutSummary:
			foutSummary.write(
				"Pkt Timestamp (Epoch), Time elapsed since capture, Time delta (Pkt Time Diff ms),"
				" AVTP timestamp, AVTP timestamp difference, Sequence Number\n")

			avtpPacketCount, packetCount, missedPktCounter, loopSeqNumCounter = 0, 0, 0, 0
			startSeqNum, endSeqNum, seqNum, seqNumDiff = None, None, None, 0
			elapsedTimeSinceCapture = 0
			nextAvtpTs, prevAvtpTs, avtpTsDiff, prevTs = 0, 0, 0, 0

			# for ts,buf in tqdm(`pcap):
			for ts, buf in pcap:
				try:
					packetCount += 1
					eth = dpkt.ethernet.Ethernet(buf)
				except dpkt.dpkt.NeedData:
					print("Found Malformed/Truncated packet. Skipping packet number {}".format(packetCount))
				except (ValueError, TypeError):
					print("Failed to parse packet. Skipping packet number {}".format(packetCount))

				# We are looking for specific packet types, so let's extract that to compare.
				if not isinstance(eth, dpkt.Packet):
					continue

				# if the type is 802.1Q vlan, then check next type ETH_TYPE_8021Q = 0x8100
				if eth.type == 0x8100:

					# some data has IP packet data some doesn't...
					if isinstance(eth.data, dpkt.ip.IP):
						ip = eth.data
						eth.data = ip.data

					# Skip processing if vlan.type has IPv6. Means this is not what we want to parse.
					# most likely just boradcast eth packets
					# and skip processing if avtp subtype does not equal 2 or 5
					try:
						if eth.vlan_tags[0].type == 0x86DD:
							continue
					except KeyError:
						print("Found DHCP packet. Skipping packet number {}".format(packetCount))
						continue

					avtpPacketCount += 1

					seqNum = eth.data[2]
					if seqNum is None:
						print("No Sequence number found")
						return

					# Find AVTP timestamp difference
					avtpSubtype = eth.data[0]
					if avtpSubtype == 3:
						currentStreamID = (hex(int.from_bytes(eth.data[4:12], byteorder='big'))).lstrip("0x")
						if currentStreamID == streamID:
							nextAvtpTs = int.from_bytes(eth.data[12:16], byteorder='big')

							avtpTsDiff = nextAvtpTs - prevAvtpTs
							prevAvtpTs = nextAvtpTs

							# Find AVTP time delta between packets
							timeDelta = (ts - prevTs) * 1000
							prevTs = ts
							elapsedTimeSinceCapture += timeDelta

							if startSeqNum is None:
								# If this is our first time through, we need to set the starting sequence number.
								startSeqNum = seqNum
								timeDelta, elapsedTimeSinceCapture = 0, 0
								foutSummary.write('%f,%f,%.4f, %i, %i,  %i\n' % (
									ts, elapsedTimeSinceCapture * 0.001, timeDelta,
									prevAvtpTs, avtpTsDiff, startSeqNum))
								continue

							# The sequence number value can range from 0-255.
							# Let's make sure we are not missing any sequence numbers in the pcap.
							if seqNum != startSeqNum and endSeqNum is not None:
								# This should be entered on the second loop, after we have already found the first sequence number.
								# If the sequence numbers are received in order, we should see an increase in that value by one.
								seqNumDiff = seqNum - endSeqNum

								# If the difference is not one, we have encountered a loop in the sequence numbers, or we missed some packets.
								if seqNumDiff == -255:
									# It's just a loop. Continue.
									loopSeqNumCounter += 1
								elif seqNumDiff != 1:
									# We have encountered a sequence number that is out of order. Mark this by increasing the counter.
									missedPktCounter += 1

							# Let's save the sequence number to compare to the next one we encounter.
							endSeqNum = seqNum

							if avtpTsDiff > maxAVTPtimestampDifference or avtpTsDiff < minAVTPtimestampDifference:
								foutSummary.write('%f,%f,%.4f, %i, %i, %i, ERROR\n' % (
									ts, elapsedTimeSinceCapture * 0.001,
									timeDelta, prevAvtpTs, avtpTsDiff, endSeqNum))
							else:
								foutSummary.write(
									'%f,%f,%.4f, %i, %i, %i\n' % (ts, elapsedTimeSinceCapture * 0.001,
																	timeDelta, prevAvtpTs, avtpTsDiff,
																	endSeqNum))

			print(
				"\nStart Sequence Number is: {} \nEnd Sequence Number is: {} \nTotal AVTP "
				"packet count is: {} "
				"\nInstances We Encountered Missed Packets is: {}"
					.format(startSeqNum, endSeqNum, avtpPacketCount, missedPktCounter))	

def getStreamIdsforVideoStreams(src):
	once = True
	with open(src, 'rb') as f:
		pcap = dpkt.pcap.Reader(f)
		print("\nChecking {} file for unqiue AVTP stream IDs".format(src))

		packetCount = 0
		uniqueStreamIds = []

		# for ts,buf in tqdm(`pcap):
		for ts, buf in pcap:
			try:
				packetCount += 1
				eth = dpkt.ethernet.Ethernet(buf)
			except dpkt.dpkt.NeedData:
				print("Found Malformed/Truncated packet. Skipping packet number {}".format(packetCount))
			except (ValueError, TypeError):
				print("Failed to parse packet. Skipping packet number {}".format(packetCount))

			# We are looking for specific packet types, so let's extract that to compare.
			if not isinstance(eth, dpkt.Packet):
				continue

			# if the type is 802.1Q vlan, then check next type ETH_TYPE_8021Q = 0x8100
			if eth.type == 0x8100:

				# some data has IP packet data some doesn't...
				if isinstance(eth.data, dpkt.ip.IP):
					ip = eth.data
					eth.data = ip.data

				# Skip processing if vlan.type has IPv6. Means this is not what we want to parse.
				# most likely just boradcast eth packets
				# and skip processing if avtp subtype does not equal 2 or 5
				if eth.vlan_tags[0].type != 0x22f0:
					continue

				avtpSubtype = eth.data[0]
				if avtpSubtype == 3:
					currentStreamID = (hex(int.from_bytes(eth.data[4:12], byteorder='big'))).lstrip("0x")
					if uniqueStreamIds:
						if currentStreamID not in uniqueStreamIds:
							uniqueStreamIds.append(currentStreamID)
					else:
						uniqueStreamIds.append(currentStreamID)

	print("Found {} unique stream Ids: {}".format(len(uniqueStreamIds), uniqueStreamIds))
	return uniqueStreamIds


uniqueStreamIds = getStreamIdsforVideoStreams(sys.argv[1])

for streamid in uniqueStreamIds:
	avtpfile = str(sys.argv[1]).split('.')[0] + "_videoAVTPtimestampdiff_for_sId_" +streamid+ ".csv"
	avtpPacketParserforSpecificStreamID(sys.argv[1], avtpfile, 249975, 250025, streamid)





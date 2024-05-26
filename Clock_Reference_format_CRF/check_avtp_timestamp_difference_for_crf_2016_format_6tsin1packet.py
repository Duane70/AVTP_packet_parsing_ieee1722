import logging
import math
import sys

import dpkt
import pandas as pd

log = logging.getLogger(__name__)


def avtpPacketParserforSpecificStreamID(src, dest, minAVTPtimestampDifference,
										maxAVTPtimestampDifference):
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
			foutSummary.write(" Sequence Number, AVTP timestamp, AVTP timestamp difference\n")

			avtpPacketCount, packetCount, missedPktCounter, loopSeqNumCounter = 0, 0, 0, 0
			startSeqNum, endSeqNum, seqNum, seqNumDiff = None, None, None, 0
			elapsedTimeSinceCapture = 0
			nextAvtpTs, prevAvtpTs, avtpTsDiff, prevTs = 0, 0, 0, 0
			currentPacketAvtpTimestamp = [0] * 6
			prevPacketAvtpTimestamp = None
			timestampDiff = [0] * 6

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

				# Process only ieee1722 AVTP packets ie
				# Check if eth type is 0x8100 (802.1Q vlan) first and then vlan eth type is 0x22f0
				if eth.type == 0x8100 and eth.vlan_tags[0].type == 0x22f0:

					avtpPacketCount += 1

					# some data has IP packet data some doesn't...
					if isinstance(eth.data, dpkt.ip.IP):
						ip = eth.data
						eth.data = ip.data

					avtpSubtype = eth.data[0]

					if avtpSubtype == 4:

						# Get AVTP Seq Number
						seqNum = eth.data[2]
						if seqNum is None:
							self.errorMsgLogAndComment("No Sequence number found")
							return

						if startSeqNum is None:
							# If this is our first time through, we need to set the starting sequence number.
							startSeqNum = seqNum
							timeDelta, elapsedTimeSinceCapture = 0, 0
							foutSummary.write("START\n")
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

						# Get AVTP timestamp difference
						currentPacketAvtpTimestamp[0] = int.from_bytes(eth.data[-48:-40], byteorder='big')
						currentPacketAvtpTimestamp[1] = int.from_bytes(eth.data[-40:-32], byteorder='big')
						currentPacketAvtpTimestamp[2] = int.from_bytes(eth.data[-32:-24], byteorder='big')
						currentPacketAvtpTimestamp[3] = int.from_bytes(eth.data[-24:-16], byteorder='big')
						currentPacketAvtpTimestamp[4] = int.from_bytes(eth.data[-16:-8], byteorder='big')
						currentPacketAvtpTimestamp[5] = int.from_bytes(eth.data[-8:], byteorder='big')
						# print(timestamp5, timestamp4, timestamp3, timestamp2, timestamp1, timestamp0)

						# calculate avtp ts diff
						timestampDiff[1] = currentPacketAvtpTimestamp[1] - currentPacketAvtpTimestamp[0]
						timestampDiff[2] = currentPacketAvtpTimestamp[2] - currentPacketAvtpTimestamp[1]
						timestampDiff[3] = currentPacketAvtpTimestamp[3] - currentPacketAvtpTimestamp[2]
						timestampDiff[4] = currentPacketAvtpTimestamp[4] - currentPacketAvtpTimestamp[3]
						timestampDiff[5] = currentPacketAvtpTimestamp[5] - currentPacketAvtpTimestamp[4]

						if prevPacketAvtpTimestamp:
							timestampDiff[0] = currentPacketAvtpTimestamp[0] - prevPacketAvtpTimestamp[5]
							foutSummary.write(
								'%i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i, %i\n' % (endSeqNum,
																								  currentPacketAvtpTimestamp[0],
																								  timestampDiff[1],
																								  currentPacketAvtpTimestamp[
																									  1],
																								  timestampDiff[2],
																								  currentPacketAvtpTimestamp[
																									  2],
																								  timestampDiff[3],
																								  currentPacketAvtpTimestamp[
																									  3],
																								  timestampDiff[4],
																								  currentPacketAvtpTimestamp[
																									  4],
																								  timestampDiff[5],
																								  currentPacketAvtpTimestamp[
																									  5],
																									  timestampDiff[0]
																									  ))
						else:
							foutSummary.write('%i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i, %i\n, %i\n' % (endSeqNum,
																  currentPacketAvtpTimestamp[0],
																  timestampDiff[1],
																  currentPacketAvtpTimestamp[1],
																  timestampDiff[2],
																  currentPacketAvtpTimestamp[2],
																  timestampDiff[3],
																  currentPacketAvtpTimestamp[3],
																  timestampDiff[4],
																  currentPacketAvtpTimestamp[4],
																  timestampDiff[5],
																  currentPacketAvtpTimestamp[5]))
							# print(currentPacketAvtpTimestamp)
							# print(prevPacketAvtpTimestamp)
							# print("xxxxxxxxxx")


						# if avtpTsDiff > maxAVTPtimestampDifference or avtpTsDiff < minAVTPtimestampDifference:
						# 	foutSummary.write('%f,%f,%.4f, %i, %i, %i, ERROR\n' % (
						# 		ts, elapsedTimeSinceCapture * 0.001,
						# 		timeDelta, prevAvtpTs, avtpTsDiff, endSeqNum))
						# else:
						# 	foutSummary.write(
						# 		'%f,%f,%.4f, %i, %i, %i\n' % (prevAvtpTs, avtpTsDiff, endSeqNum))

						prevPacketAvtpTimestamp = currentPacketAvtpTimestamp.copy()

			print(
				"\nStart Sequence Number is: {} \nEnd Sequence Number is: {} \nTotal AVTP "
				"packet count is: {} "
				"\nInstances We Encountered Missed Packets is: {}"
				.format(startSeqNum, endSeqNum, avtpPacketCount, missedPktCounter))


avtpfile = str(sys.argv[1]).split('.')[0] + "_AVTPtimestampdiff_for_sId.csv"
avtpPacketParserforSpecificStreamID(sys.argv[1], avtpfile, 249975, 250025)

from PyQt4 import QtGui, QtCore
import pcapParseUi
import queue
import sys
import os
import shutil
import subprocess
import pyaudio
import time
import threading
import struct
import binascii
import wave
import ctypes
import bitarray
import datetime
import pickle
import math
import logging
import logging.config
import json
import gc
# from pympler.tracker import SummaryTracker
# tracker = SummaryTracker()

from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as pl
import numpy as np
import multiprocessing as mp
from tempfile import TemporaryFile, NamedTemporaryFile

if os.name == 'nt':
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    screenWidth, screenHeight = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
else: # os.name == 'posix':
    screenWidth = 1680

# sys.setcheckinterval = 20
# logging.disable(logging.CRITICAL)

def setup_logging(default_path='logging.json'):
    try:
        os.makedirs('log', exist_ok = True)
    except Exception as e:
        print('make log dir error!', e)
    path = default_path
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': False,
        
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                },
            },
            'handlers': {
                'default': {
                    'level':'INFO',    
                    'class':'logging.handlers.TimedRotatingFileHandler',
                    'filename': 'log/pcapParseGui.log',
                    'formatter': 'standard'
                },  
            },
            'loggers': {
                'MainThrd': {
                    'handlers': ['default'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'pcmPlayProcess': {
                    'handlers': ['default'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'pcmPlayThread': {
                    'handlers': ['default'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'parserThr': {
                    'handlers': ['default'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'decodeThr': {
                    'handlers': ['default'],
                    'level': 'DEBUG',
                    'propagate': False
                }
            }
        })

mainTitle = 'PcapParse '
availableAmrOpt = ['amr', 'amr-wb', 'amr_octet-align', 'amr-wb_octet-align', 'h264']
tableHeaders = ['source ip','srcPort','dest ip','destPort','first packet time','last packet time','pktCount','PT','SSRC','codec','Lost','Dup','WrongSeq','MaxDelta(s/seq)'] #,'MaxJitter','MeanJitter']

CHANNELS = 1
THRESHOLD = 500
CHUNK_SIZE = 1024
FORMAT = pyaudio.paInt16
RATE = 8000
STEP = 0.08    # 0.02 means 20ms

def processPlayPcm(q, pcmRate, pcmData, playState, positionInd, logQueue):
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=pcmRate, output=True)
    playPosition = visagePosition = positionInd.value
    logQueue.put(['info', 'pcmRate: %s, startPosition: %s' % (pcmRate, positionInd.value)])
    while playPosition < len(pcmData) and os.getppid():
        if visagePosition == positionInd.value:
            pass
        else:
            playPosition = visagePosition = positionInd.value
        if playState.value == 1:
            stream.write(pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])
            logQueue.put(['debug', 'pcmPlayer writing data %s %s %s' % (playPosition, playPosition + 2 * int(pcmRate * STEP), pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])])
            playPosition = playPosition + 2 * int(pcmRate * STEP)
            try:
                logQueue.put(['debug', ('pcmPlayer process feedback play position at %s' % playPosition)])
                q.put(playPosition)
            except Exception as e:
                logQueue.put(['error', 'pcmPlayer process failed to write playPosition into feedback queue'])
                stream.stop_stream()
                stream.close()
                p.terminate()
                break
        elif playState.value == 2:
            time.sleep(0.5)
        elif playState.value == 0:
            stream.stop_stream()
            stream.close()
            p.terminate()
            break

def pcmPlayerProcessLogger(playState, logQueue, logger):
    logger.info('pcmPlayerProcessLogger thread normal start')
    while playState.value:
        try:
            logData = logQueue.get(block = False)
            if logData[0] == 'info':
                logger.info(logData[1])
            elif logData[0] == 'debug':
                logger.debug(logData[1])
            elif logData[0] == 'error':
                logger.error(logData[1])
            else:
                logger.error(logData)
        except queue.Empty:
            time.sleep(0.3)
            continue
        except Exception as e:
            logger.error('pcmPlayerProcessLogger thread unknown error', exc_info=True)
    logger.info('pcmPlayerProcessLogger thread normal exit')

class pcmPlayer(QtCore.QThread):
    def __init__(self, pcmData, start = 0, pcmRate = RATE):
        QtCore.QThread.__init__(self)
        self.logger = logging.getLogger('pcmPlayThread')
        self.state = 0    #state:0 stopped, 1 playing, 2 paused
        self.pcmData = pcmData
        self.pcmRate = pcmRate
        self.updatePlotCount = 0
        self.playState = mp.Value('I', self.state)
        self.positionInd = mp.Value('I', start)
        self.p = None
        self.q = mp.Queue()
        self.linePosition = 0
        self.logger.info('pcmPlayer Thread initiated')
        self.pcmPlayProcessLogger = logging.getLogger('pcmPlayProcess')
        self.logQueue = mp.Queue()
        if hasattr(self, 'logThr'):
            self.logger.info('child thread logThr whether still alive: %s', self.logThr.isAlive())
        else:
            self.logger.info('pcmPlayer have no logThr child')
        self.logThr = threading.Thread(target=pcmPlayerProcessLogger, args =(self.playState, self.logQueue, self.pcmPlayProcessLogger))
        self.logThr.daemon = True
        self.state = 1
        self.playState.value = 1
        self.logThr.start()
        self.logger.debug('pcmPlayer initiated, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def run(self):
        self.p = mp.Process(target=processPlayPcm, args=(self.q, self.pcmRate, self.pcmData, self.playState, self.positionInd, self.logQueue))
        self.p.daemon = True
        self.p.start()
        self.logger.info('pcm audio length: %s seconds', len(self.pcmData) / 2 / self.pcmRate)
        while self.p.is_alive():
            try:
                self.linePosition = self.q.get(block = False)
                self.emit(QtCore.SIGNAL('refreshMatplotLine(float)'), self.linePosition/len(self.pcmData))
                self.logger.debug('feedback progress ratio to main thread: %s', self.linePosition/len(self.pcmData))
            except queue.Empty:
                if self.state == 1:
                    time.sleep(0.01)
                elif self.state == 2:
                    time.sleep(0.5)
                continue
            except Exception as e:
                self.logger.error('pcmPlayer thread feedback get error', exc_info=True)
        self.logger.info('pcmPlayer Thread normally exited')
        self.logger.debug('pcmPlayer normal finished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def swapState(self):
        if self.state == 0 or self.state == 2:
            self.state = 1
            self.playState.value = 1
            self.logger.info('pcmPlayer Thread resume playing')
        elif self.state == 1:
            self.state = 2
            self.playState.value = 2
            self.logger.info('pcmPlayer Thread paused')

    def stop(self):
        self.state = 0
        self.playState.value = 0
        self.logger.debug('pcmPlay process is still alive %s', self.p.is_alive())
        time.sleep(0.2)
        self.logger.info('pcmPlayer Thread stopped')
        if self.p.is_alive() == True:
            self.p.terminate()
            self.p.join()

def getRtpTimeStampEndPoint(currentTimeStamp, timeLength):
    return (currentTimeStamp + timeLength) % 4294967296

class multiDecoder(mp.Process):
    def __init__(self, parentState, jobQueue, feedbackQueue, logLevel, logQueue):
        super(multiDecoder, self).__init__() # super().__init__()
        self.parentState = parentState
        self.jobQueue = jobQueue
        self.feedbackQueue = feedbackQueue
        self.logLevel = logLevel
        self.logQueue = logQueue
        self.bit_amr_wb_list = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0]
        self.bit_amr_nb_list = [95, 103, 118, 134, 148, 159, 204, 244, 39, 0, 0, 0, 0, 0, 0, 0]
        self.processName = str(mp.current_process())
        self.currentJob = None
        
    def run(self):
        global decodeInfo
        decodeInfo = ''
        while self.jobQueue.qsize() > 0:
            if not self.parentState.value:
                return
            try:
                jobContent = self.jobQueue.get(block = False)
            except Exception as e:
                self.feedbackQueue.put(['', self.processName, 'error', str(e)])
                return
            self.currentJob = jobContent[0]
            self.feedbackQueue.put([jobContent[0], self.processName, 'start', str(datetime.datetime.now())])
            try:
                try:
                    with open(jobContent[2], 'rb') as amrPayloadFile, open(jobContent[3], 'rb') as seqFile, open(jobContent[4], 'rb') as timeStampFile:
                        rtpPayload, seq, timeStamp = pickle.load(amrPayloadFile), pickle.load(seqFile), pickle.load(timeStampFile)
                except Exception as e:
                    self.feedbackQueue.put([jobContent[0], self.processName, 'error', 'open cache file error'])
                    self.logQueue.put([self.processName, 'error', str(e)])
                    continue
                if jobContent[1] == 'amr':
                    rawData = self.amrDecode(rtpPayload, timeStamp, seq, 'Nb')[0]
                elif jobContent[1] == 'amr-wb':
                    rawData = self.amrDecode(rtpPayload, timeStamp, seq, 'Wb')[0]
                elif jobContent[1] == 'amr_octet-align':
                    rawData = self.amrDecode(rtpPayload, timeStamp, seq, 'Nb', True)[0]
                elif jobContent[1] == 'amr-wb_octet-align':
                    rawData = self.amrDecode(rtpPayload, timeStamp, seq, 'Wb', True)[0]
                elif jobContent[1] == 'h264':
                    rawData = self.h264Decode(rtpPayload, timeStamp, seq)[0]
                else:
                    self.feedbackQueue.put([jobContent[0], self.processName, 'error', 'unknown payload type! %s' % jobContent[1]])
                    self.logQueue.put([self.processName, 'error', 'unknown payload type! %s' % jobContent[1]])
                if rawData:
                    output = NamedTemporaryFile(mode='wb', delete=False)
                    output.write(rawData)
                    output.flush()
                    output.close()
                    self.feedbackQueue.put([jobContent[0], self.processName, 'finish', [output.name, len(rawData), decodeInfo]])
                    self.logQueue.put([self.processName, 'info', str([output.name, len(rawData)])])
            except Exception as e:
                # raise
                self.feedbackQueue.put(['', self.processName, 'error', 'just exit'])
                self.logQueue.put([self.processName, 'error', str(e)])
        self.feedbackQueue.put(['', self.processName, 'done', 'exiting'])
        self.logQueue.put(['', self.processName, 'info', 'exiting'])

    def amrDecode(self, amrList, rtpTimeStampList, seqNumber, WbOrNb, octetAligned = False):
        global decodeInfo
        frames = 0
        pcm = b''
        processInt = 0
        shortCounter = 0
        longerCounter = 0
        timeStampPointer = rtpTimeStampList[0]
        if WbOrNb == 'Wb':
            timeStampThresh = 9600000
            sidToken = 9
            unitType, unitNum = '320h', 320
            bitAmrList = self.bit_amr_wb_list         
            dll = ctypes.CDLL(r'amrWbDecoder.dll')
            cDecodeFunc = dll.D_IF_decode
            serial_Array = ctypes.c_ubyte * 61
            serial = serial_Array(0)
            synth_Array = ctypes.c_short * 320
            synth = synth_Array(0)
            destate = dll.D_IF_init()
        elif WbOrNb == 'Nb':
            timeStampThresh = 4800000
            sidToken = 8
            unitType, unitNum = '160h', 160
            bitAmrList = self.bit_amr_nb_list
            dll = ctypes.CDLL(r'amrNbDecoder.dll')
            cDecodeFunc = dll.Decoder_Interface_Decode
            serial_Array = ctypes.c_ubyte * 32
            serial = serial_Array(0)
            synth_Array = ctypes.c_short * 160
            synth = synth_Array(0)
            destate = dll.Decoder_Interface_init()
        while(frames < len(amrList)):
            if not self.parentState.value:
                decodeInfo = 'decoding cancelled'
                return b'', 0
            if frames*100/len(amrList)>=processInt:
                processInt = processInt + 1
                self.feedbackQueue.put([self.currentJob, self.processName, 'process', processInt])
            timeStampStartPoint = 0
            if 0 < rtpTimeStampList[frames] - timeStampPointer < timeStampThresh:
                pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames] - timeStampPointer)
                self.logQueue.put([self.processName, 'error', 'packet timeStamp gap found, padding length: %s, maybe due to packet lost. frameNumber: %s, seqNumber: %s, rtpTimeStamp: %s' % (rtpTimeStampList[frames] - timeStampPointer, frames, seqNumber[frames] , rtpTimeStampList[frames])])
            elif 0 < timeStampPointer - rtpTimeStampList[frames] < timeStampThresh:
                timeStampStartPoint = timeStampPointer - rtpTimeStampList[frames] + (timeStampPointer - rtpTimeStampList[frames])%2
                self.logQueue.put([self.processName, 'error', 'packet timeStamp overlap found, filling, maybe due to wrong sequence, rewriting pcm output. frameNumber: %s, seqNumber: %s, rtpTimeStamp: %s' % (frames, seqNumber[frames] , rtpTimeStampList[frames])])
            elif 0 < timeStampPointer + 4294967296 - rtpTimeStampList[frames] < timeStampThresh:
                timeStampStartPoint = timeStampPointer + 4294967296 - rtpTimeStampList[frames] + (timeStampPointer + 4294967296 - rtpTimeStampList[frames])%2
                self.logQueue.put([self.processName, 'error', 'packet timeStamp overlap found, filling, maybe due to wrong sequence, rewriting pcm output. frameNumber: %s, seqNumber: %s, rtpTimeStamp: %s' % (frames, seqNumber[frames] , rtpTimeStampList[frames])])
            elif 0 < rtpTimeStampList[frames] + 4294967296 - timeStampPointer < timeStampThresh:
                pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames] + 4294967296 - timeStampPointer)
                self.logQueue.put([self.processName, 'error', 'packet timeStamp gap found, padding length: %s, maybe due to packet lost. frameNumber: %s, seqNumber: %s, rtpTimeStamp: %s' % (rtpTimeStampList[frames] + 4294967296 - timeStampPointer, frames, seqNumber[frames] , rtpTimeStampList[frames])])
                
            amrPacketTocList = []
            if octetAligned:
                followByBitPointer = 8
            else:
                followByBitPointer = 4
            bitAmrPayload = bitarray.bitarray(endian='big')
            bitAmrPayload.frombytes(amrList[frames])
            while followByBitPointer + 6 < len(bitAmrPayload):
                intToc = int(bitAmrPayload[followByBitPointer+1:followByBitPointer+5].to01(), 2)
                amrPacketTocList.append(intToc)
                if bitAmrPayload[followByBitPointer] == False:
                    break
                if octetAligned:
                    followByBitPointer = followByBitPointer + 8
                else:
                    followByBitPointer = followByBitPointer + 6
            if octetAligned:
                amrPayloadPointer = followByBitPointer + 8
            else:
                amrPayloadPointer = followByBitPointer + 6
            if self.logLevel == 'debug':
                self.logQueue.put([self.processName, 'debug', 'frameNumber: %s, rtpContent: %s, seqNumber: %s, rtpTimeStamp: %s' % (frames, amrList[frames], seqNumber[frames] , rtpTimeStampList[frames])])
            for t in amrPacketTocList:
                if t < sidToken:
                    T = bitarray.bitarray('0')
                    T.extend(bin(t)[2:].zfill(4))
                    T.extend('100')
                    if amrPayloadPointer + bitAmrList[t] < len(bitAmrPayload):
                        AmrPayload = T.tobytes() + bitAmrPayload[amrPayloadPointer : amrPayloadPointer + bitAmrList[t]].tobytes()
                        if self.logLevel == 'debug':
                            self.logQueue.put([self.processName, 'debug', 'AmrPayload: %s' % AmrPayload])
                        for i in range(len(AmrPayload)):
                            serial[i] = AmrPayload[i]
                        cDecodeFunc(destate, serial, synth, 0)
                        if timeStampStartPoint > 0:# this is for wrong seq
                            pcm = pcm[:len(pcm) - timeStampStartPoint * 2] + struct.pack(unitType, *synth[:unitNum]) + pcm[len(pcm) - timeStampStartPoint * 2 + unitNum * 2:]
                            timeStampStartPoint = timeStampStartPoint - unitNum
                            if self.logLevel == 'debug':
                                self.logQueue.put([self.processName, 'debug', 'rewriting 160h pcm at position: %s' % len(pcm) - timeStampStartPoint * 2])
                        elif timeStampStartPoint == 0:
                            pcm = pcm + struct.pack(unitType, *synth[:unitNum])
                            if self.logLevel == 'debug':
                                self.logQueue.put([self.processName, 'debug', 'normal appending pcm 160h'])
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(bitAmrList[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + bitAmrList[t]
                        timeStampPointer = getRtpTimeStampEndPoint(rtpTimeStampList[frames], unitNum)
                    else:
                        shortCounter = shortCounter + 1
                        self.logQueue.put([self.processName, 'error', 'not enough payload! rtpTimeStamp: %s, seqNumber: %s' % (rtpTimeStampList[frames], seqNumber[frames])])
                else:
                    if t == sidToken:
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(bitAmrList[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + bitAmrList[t]
                    self.logQueue.put([self.processName, 'error', 'amr Toc == %s, padding it, rtpTimeStamp: %s, seqNumber: %s' % (t, rtpTimeStampList[frames], seqNumber[frames])])
                    if len(rtpTimeStampList) == frames + 1:# last packet
                        pcm = pcm + b'\x00\x00' * unitNum * 8 # 1280
                        if self.logLevel == 'debug':
                            self.logQueue.put([self.processName, 'debug', 'appending silent pcm %sh' % unitNum * 8])
                    elif 0 < rtpTimeStampList[frames+1] - rtpTimeStampList[frames] < timeStampThresh:# maybe gap, just fill all with silence, max length 10mins, 8000*60*10 = 4800000 means 10 minutes
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] - rtpTimeStampList[frames])
                        if self.logLevel == 'debug':
                            self.logQueue.put( [self.processName, 'debug', 'appending silent pcm %sh' % (rtpTimeStampList[frames+1] - rtpTimeStampList[frames])] )
                        timeStampPointer = rtpTimeStampList[frames+1]
                    elif 0 < rtpTimeStampList[frames+1] + 4294967296 - rtpTimeStampList[frames] < timeStampThresh:# round back gap
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] + 4294967296 - rtpTimeStampList[frames])
                        if self.logLevel == 'debug':
                            self.logQueue.put([self.processName, 'debug', 'appending silent pcm %sh' % (rtpTimeStampList[frames+1] + 4294967296 - rtpTimeStampList[frames])])
                        timeStampPointer = rtpTimeStampList[frames+1]
                    else:
                        self.logQueue.put([self.processName, 'error', 'wrong or dup sequence, or the gap too large when decoding, rtp should be unique and sorted after parsing. rtpTimeStamp: %s, seqNumber: %s' % (rtpTimeStampList[frames], seqNumber[frames])])
            if len(bitAmrPayload) - amrPayloadPointer >= 8:
                longerCounter = longerCounter + 1
                self.logQueue.put([self.processName, 'error', 'payload longer than expected! rtpTimeStamp: %s, seqNumber: %s, amrPayloadPointer: %s, len_bitAmrPayload: %s' % (rtpTimeStampList[frames], seqNumber[frames], amrPayloadPointer, len(bitAmrPayload))])
            frames = frames + 1
        if longerCounter > 0:
            decodeInfo = decodeInfo + str(longerCounter) + ' amr packet longer than expected! '
        if shortCounter > 0:
            decodeInfo = decodeInfo + str(shortCounter) + ' amr packet shorter than expected!'
        return pcm, frames

    def h264Decode(self, payloadList, rtpTimeStampList, seqList):
        global decodeInfo
        frames = 0
        processInt = 0
        payload = b''
        while(frames < len(payloadList)):
            if not self.parentState.value:
                decodeInfo = 'decoding cancelled'
                return b'', 0
            if frames*100/len(payloadList) >= processInt:
                processInt = processInt + 1
                self.feedbackQueue.put([self.currentJob, self.processName, 'process', processInt])
            if self.logLevel == 'debug':
                self.logQueue.put([self.processName, 'debug', 'current packet FU: %s, rtpTimeStamp: %s, seqNumber: %s' % (payloadList[frames][0:2], rtpTimeStampList[frames], seqList[frames])])
            naluHeader = bitarray.bitarray(endian='big')
            naluHeader.frombytes(payloadList[frames][0:2])
            if int(naluHeader[3:8].to01(), 2) == 28:
                if naluHeader[8]:
                    naluHeader = (naluHeader[:3] + naluHeader[11:]).tobytes()
                    if self.logLevel == 'debug':
                        self.logQueue.put([self.processName, 'debug', 'writing payload header, header: %s' % naluHeader])
                    payload = payload + b'\x00\x00\x00\x01' + naluHeader
                if self.logLevel == 'debug':
                    self.logQueue.put([self.processName, 'debug', 'writing payload: %s' % payloadList[frames][2:]])
                payload = payload + payloadList[frames][2:]
            elif int(naluHeader[3:8].to01(), 2) <= 8:
                payload = payload + b'\x00\x00\x00\x01' + payloadList[frames]
                if self.logLevel == 'debug':
                    self.logQueue.put([self.processName, 'debug', 'writing payload sps/pps or other nal, header: %s' % payloadList[frames][0:1]])
            else:
                if self.logLevel == 'debug':
                    self.logQueue.put([self.processName, 'debug', 'unknown FU identity: %s, rtpTimeStamp: %s, seqNumber: %s' % (bin(payloadList[frames][0])[2:].zfill(8), rtpTimeStampList[frames], seqList[frames])])
            frames = frames + 1
        return payload, frames

def multiDecodeProcessLogger(decoderThrState, logQueue, logger):
    logger.info('multiParsePcapProcessLogger thread normal start')
    while decoderThrState.value:
        try:
            logData = logQueue.get(block = False)
            if logData[0] == 'info':
                logger.info(logData[0], logData[2])
            elif logData[0] == 'debug':
                logger.debug(logData[0], logData[2])
            elif logData[0] == 'error':
                logger.error(logData[0], logData[2])
            else:
                logger.error(logData)
        except queue.Empty:
            time.sleep(0.3)
            continue
        except Exception as e:
            logger.error('multiParsePcapProcessLogger thread unknown error', exc_info=True)
    logger.info('multiParsePcapProcessLogger thread normal exit')
    
class multiDecoderThread(QtCore.QThread):
    def __init__(self, jobIndexList, jobTypeList, loggerHandlerLevel, Fast_Decode = False):
        QtCore.QThread.__init__(self)
        self.jobIndexList = jobIndexList
        self.jobTypeList = jobTypeList
        self.level = loggerHandlerLevel
        self.Fast_Decode = Fast_Decode
        self.processingJob = None
        self.logger = logging.getLogger('decodeThr')
        self.decoderThrState = mp.Value('I', 0)
        self.feedbackQ = mp.Queue()
        self.logQ = mp.Queue()
        self.jobQ = mp.Queue()
        self.logger.info('multiDecoderThread initiated')
        self.subProcessList = []
        self.failList = []
        self.successList = []
        
    def stop(self):
        global decodeInfo
        decodeInfo = 'decode cancelled'
        self.decoderThrState.value = 0
        self.logger.info('multiDecoderThread get stop event')

    def run(self):
        global pcmList
        global parseResult
        global decodeInfo
        decodeInfo = ''
        self.decoderThrState.value = 1
        for i in range(len(self.jobIndexList)):
            self.jobQ.put([self.jobIndexList[i], self.jobTypeList[i], parseResult[self.jobIndexList[i]][7], parseResult[self.jobIndexList[i]][10], parseResult[self.jobIndexList[i]][11]])
        self.logThr = threading.Thread(target=multiDecodeProcessLogger, args =(self.decoderThrState, self.logQ, self.logger))
        self.logThr.daemon = True
        self.logThr.start()
        # if self.Fast_Decode:
        #     numberOfProcess = os.cpu_count()
        # else:
        numberOfProcess = 1
        for i in range(numberOfProcess):
            p = multiDecoder(self.decoderThrState, self.jobQ, self.feedbackQ, self.level, self.logQ)
            p.daemon = True # assert self._popen is None, 'process has already started'
            self.subProcessList.append(p)
            p.start()

        while self.decoderThrState.value and p.is_alive():
            try:
                M = self.feedbackQ.get(block = False)   #M[0] index, M[1]processName, M[2]process, start, finish, error, M[3]processInd, detailed error
                self.logger.debug('%s', str(M))
                if M[2] == 'process':
                    if  M[0] == self.processingJob[0]:
                        self.processingJob[1] = M[3]
                        self.emit(QtCore.SIGNAL('refreshProgressBar(QString, int)'), 'index' + str(M[0] + 1), M[3])
                        self.logger.debug('multiDecoderThread update statusBar: %s, %s', self.processingJob[0], M[3])
                    else:
                        self.logger.error('multiDecoderThread severe error: get feedback no longer in processing list')
                elif M[2] == 'start':
                    self.processingJob = [M[0], 0]
                    self.logger.info('decode start: %s, %s, %s', M[0], M[1], M[3])
                elif M[2] == 'finish': # M[3] 0 output.name, 1 length, 2 decodeInfo
                    self.successList.append(M[0])
                    pcmList[M[0]][0] = M[3][0]
                    if self.jobTypeList[self.jobIndexList.index(M[0])] == 'amr' or self.jobTypeList[self.jobIndexList.index(M[0])] == 'amr_octet-align':
                        pcmList[M[0]][1] = 8000
                    elif self.jobTypeList[self.jobIndexList.index(M[0])] == 'amr-wb' or self.jobTypeList[self.jobIndexList.index(M[0])] == 'amr-wb_octet-align':
                        pcmList[M[0]][1] = 16000
                    elif self.jobTypeList[self.jobIndexList.index(M[0])] == 'h264':
                        pcmList[M[0]][1] = ''
                    pcmList[M[0]][2] = parseResult[M[0]][4]
                    pcmList[M[0]][4] = M[3][1]
                    decodeInfo = M[3][2]
                    self.logger.info('decode done: %s, %s, %s', M[0], M[1], str(datetime.datetime.now()))
                elif M[2] == 'error':
                    if type(M[0]) == int:
                        pcmList[M[0]][0] = None
                        pcmList[M[0]][3] = None
                        pcmList[M[0]][4] = None
                    self.logger.error('decode process unknown error: %s, %s, %s', M[0], M[1], M[3])
                    try:
                        self.failList.append(M[0])
                    except Exception as e:
                        self.logger.error('unknown error', exc_info=True)
            except queue.Empty:
                time.sleep(0.01)
            except Exception as e:
                self.logger.error('multiDecoderThread feedback get error', exc_info=True)
        
        self.logger.info('multiDecoderThread normally exited')
        self.logger.debug('multiDecoderThread normal finished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.decoderThrState.value = 0

def multiParser(parserThrState, jobQ, refreshQ, level, logQ):
    processName = str(mp.current_process())
    while jobQ.qsize() > 0:
        try:
            pcapFileName = jobQ.get(block = False)
        except Exception as e:
            refreshQ.put(['', processName, 'error', str(e)])
            return
        
        refreshQ.put([pcapFileName, processName, 'start', str(datetime.datetime.now())])
        try:
            with open(pcapFileName,'rb') as fpcap:
                string_data = fpcap.read()
        except Exception as e:
            logQ.put([processName,'error', str(e)])
            refreshQ.put([pcapFileName, processName, 'error','open pcap File failed'])
            return
        if string_data[:4] != b'\xd4\xc3\xb2\xa1':
            logQ.put([processName,'error', 'probably not a pcap file %s' % pcapFileName])
            refreshQ.put([pcapFileName, processName, 'error','probably not a pcap file!!!'])
            return
        #pcap header
        pcap_header = {}
        pcap_header['magic_number'] = string_data[0:4]
        pcap_header['version_major'] = string_data[4:6]
        pcap_header['version_minor'] = string_data[6:8]
        pcap_header['thiszone'] = string_data[8:12]
        pcap_header['sigfigs'] = string_data[12:16]
        pcap_header['snaplen'] = string_data[16:20]
        pcap_header['linktype'] = string_data[20:24]
        if level == 'debug':
            logQ.put([processName,'debug', 'pcap file header %s' % pcap_header])
        #pcap packet
        step = 0
        packet_num = 0
        packet_data = []
        pcap_packet_header = {}
        EthernetII={}
        ip={}
        udp={}
        rtp={}
        rtpHashMap = {}
        filename_arr=[]
        globalSeq = [] # [[min, max, rollOver Count, wrongSeq],]
        maxTimeDeltaList = [] # [[maxTimeDelta, maxTimeDelta rtp seq],]
        iStartPos = 24
        filename_count=0
        filename_arr_count=0
        processInt=0
        while(iStartPos < len(string_data)):
            if not parserThrState.value:
                return
            if iStartPos * 100 / len(string_data) >= processInt:
                processInt = processInt + 1
                refreshQ.put([pcapFileName, processName, 'process', processInt])
            pcap_packet_header['GMTtime'] = string_data[iStartPos : iStartPos + 4]
            pcap_packet_header['MicroTime'] = string_data[iStartPos + 4 : iStartPos + 8]
            pcap_packet_header['caplen'] = string_data[iStartPos + 8 : iStartPos + 12]
            pcap_packet_header['len'] = string_data[iStartPos + 12 : iStartPos + 16]
            timeStamp,= struct.unpack('<I', pcap_packet_header['GMTtime'])
            microtime,= struct.unpack('<I', pcap_packet_header['MicroTime'])
            timeArray = time.localtime(timeStamp)         
            PacketTime = str(time.strftime("%Y-%m-%d %H:%M:%S", timeArray))+'.'+str(microtime)         
            packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
            each_packet_data = string_data[iStartPos + 16 : iStartPos + 16 + packet_len]
            if level == 'debug':
                logQ.put([processName,'debug', 'packet number: %s, pcap packet header: %s' % (packet_num, pcap_packet_header)])
            if packet_len>54:
                #Ethernet II
                EthernetII['addr_source'] = string_data[iStartPos + 16 : iStartPos + 16 + 6]
                EthernetII['addr_to'] = string_data[iStartPos + 16 + 6 : iStartPos + 16 + 6 + 6]      
                EthernetII['type'] = string_data[iStartPos + 16 + 6 + 6 : iStartPos + 16 + 6 + 6 + 2]  
                if level == 'debug':
                    logQ.put([processName,'debug', 'EthernetII header: %s' % EthernetII])
                #ip
                ip['version'] = string_data[iStartPos + 30 : iStartPos + 31]
                ipversion, = struct.unpack('B',ip['version'])
                if str(hex(ipversion))[2] == "4":
                    #ipv4
                    if str(hex(ipversion))[3] != "5":
                        logQ.put([processName,'debug', 'ip header length: %s, hard code for 20 only! packet number: %s' % (int(hex(ipversion)[3]) * 4, pcap_packet_header)])
                        continue
                    ip['protocol'] = string_data[iStartPos + 30 + 9:iStartPos + 30 + 10]
                    ip['addr_source'] = string_data[iStartPos + 30 + 12:iStartPos + 30 + 16]
                    ip['addr_to'] = string_data[iStartPos + 30 + 16:iStartPos + 30 + 20]
                    ip1,ip2,ip3,ip4 = struct.unpack('4B',ip['addr_source'])
                    ip_addr_from = str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
                    ip1,ip2,ip3,ip4 = struct.unpack('4B',ip['addr_to'])
                    ip_addr_to = str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
                    protocol, = struct.unpack('B',ip['protocol'])
                    iOffset = 0
                else:
                    ip['protocol'] = string_data[iStartPos + 30 + 6:iStartPos + 30 + 7]
                    ip['addr_source'] = string_data[iStartPos + 30 + 8:iStartPos + 30 + 8 + 16]
                    ip['addr_to'] = string_data[iStartPos + 30 + 8 + 16:iStartPos + 30 + 8 + 16 + 16]
                    ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8 = struct.unpack('>8H',ip['addr_source'])
                    ip_addr_from = hex(ip1).replace('0x','')+':'+hex(ip2).replace('0x','')+':'+hex(ip3).replace('0x','')+':'+hex(ip4).replace('0x','')+':'+hex(ip5).replace('0x','')+':'+hex(ip6).replace('0x','')+':'+hex(ip7).replace('0x','')+':'+hex(ip8).replace('0x','')
                    ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8 = struct.unpack('>8H',ip['addr_to'])
                    ip_addr_to = hex(ip1).replace('0x','')+':'+hex(ip2).replace('0x','')+':'+hex(ip3).replace('0x','')+':'+hex(ip4).replace('0x','')+':'+hex(ip5).replace('0x','')+':'+hex(ip6).replace('0x','')+':'+hex(ip7).replace('0x','')+':'+hex(ip8).replace('0x','')
                    protocol, = struct.unpack('B',ip['protocol'])
                    iOffset = 20
                if level == 'debug':
                    logQ.put([processName,'debug', 'ip header: %s' % ip])
                if protocol==17:
                    #udp
                    udp['source_port'] = string_data[iStartPos + iOffset + 50:iStartPos + iOffset + 50 + 2]
                    udp['dest_port'] = string_data[iStartPos + iOffset + 50 + 2:iStartPos + iOffset + 50 + 4]
                    udp['length'] = struct.unpack('>H', string_data[iStartPos + iOffset + 50 + 4:iStartPos + iOffset + 50 + 6])[0]
                    port1, = struct.unpack('>H',udp['source_port'])
                    port2, = struct.unpack('>H',udp['dest_port'])
                    if level == 'debug':
                        logQ.put([processName,'debug', 'udp header: %s' % udp])
                    if port1 >= 10000 and port2 >= 10000 and len(string_data[iStartPos + iOffset + 58 : iStartPos + 16 + packet_len]) >= 15:
                        #rtp
                        rtp['first_two_byte'] = string_data[iStartPos + iOffset + 58 : iStartPos + iOffset + 58 + 2]
                        rtp['payload_type'] = string_data[iStartPos + iOffset + 58 + 1 : iStartPos + iOffset + 58 + 2]
                        payload_type, = struct.unpack('B',rtp['payload_type'])
                        payload_type_num = int(payload_type&0b01111111)
                        rtp['seq_number'] = struct.unpack('>H', string_data[iStartPos + iOffset + 58 + 2:iStartPos + iOffset + 58 + 4])[0]
                        rtp['timestamp'] = struct.unpack('>L', string_data[iStartPos + iOffset + 58 + 4:iStartPos + iOffset + 58 + 8])[0]
                        rtp['SSRC'] = binascii.hexlify(string_data[iStartPos + iOffset + 58 + 8:iStartPos + iOffset + 58 + 12]).upper()
                        rtp['payload'] = string_data[iStartPos + iOffset + 58 + 12:iStartPos + 16 + packet_len]
                        if level == 'debug':
                            logQ.put([processName,'debug', 'rtp header: %s' % rtp])
                        if 96 <= payload_type_num <= 127:
                            if rtpHashMap.get(string_data[iStartPos + iOffset + 56:iStartPos + iOffset + 58 + 12]) == None:
                                rtpHashMap[string_data[iStartPos + iOffset + 56:iStartPos + iOffset + 58 + 12]] = ''
                                existFlag = False
                                j = 0
                                while j < filename_arr_count:
                                    if filename_arr[j][0]==ip_addr_from and filename_arr[j][1]==str(port1) and filename_arr[j][2]==ip_addr_to and filename_arr[j][3]==str(port2) and filename_arr[j][8]=='PT'+str(payload_type_num) and filename_arr[j][9]==rtp['SSRC']:
                                        tempTimeDelta = datetime.datetime.strptime(PacketTime, "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(filename_arr[j][5], "%Y-%m-%d %H:%M:%S.%f")
                                        if tempTimeDelta.total_seconds() > maxTimeDeltaList[j][0]:
                                            maxTimeDeltaList[j] = [tempTimeDelta.total_seconds(), rtp['seq_number']]
                                        filename_arr[j][5]=PacketTime
                                        filename_arr[j][6]=filename_arr[j][6]+1
                                        
                                        if rtp['seq_number'] + 65536 * globalSeq[j][2] > globalSeq[j][1]:
                                            globalSeq[j][1] = rtp['seq_number'] + 65536 * globalSeq[j][2]
                                        elif rtp['seq_number'] + 65536 * globalSeq[j][2] < globalSeq[j][0]:
                                            globalSeq[j][0] = rtp['seq_number'] + 65536 * globalSeq[j][2]
                                        if rtp['seq_number'] == 65535:
                                            globalSeq[j][2] = globalSeq[j][2] + 1
                                            
                                        if rtp['seq_number'] - filename_arr[j][10][-1] == 1 or (filename_arr[j][10][-1] == 65535 and rtp['seq_number'] == 0):
                                            filename_arr[j][7].append(rtp['payload'])
                                            filename_arr[j][10].append(rtp['seq_number'])
                                            filename_arr[j][11].append(rtp['timestamp'])
                                            if level == 'debug':
                                                logQ.put([processName,'debug', 'appending rtp payload to existing stream'])
                                        else:
                                            if 1 < rtp['seq_number'] - filename_arr[j][10][-1] < 3000 or 1 < rtp['seq_number'] + 65536 - filename_arr[j][10][-1] < 3000:# 3000 = 50*60*1 means 1min packet gap
                                                logQ.put([processName,'error', 'rtp seq gap: %s, appending rtp payload to the stream end, rtp seq: %s' % (rtp['seq_number'] - filename_arr[j][10][-1], rtp['seq_number'])])
                                                filename_arr[j][7].append(rtp['payload'])
                                                filename_arr[j][10].append(rtp['seq_number'])
                                                filename_arr[j][11].append(rtp['timestamp'])
                                            elif 0 < filename_arr[j][10][-1] - rtp['seq_number'] < 3000:
                                                for s in range(len(filename_arr[j][10])):
                                                    if filename_arr[j][10][-1 - s] < rtp['seq_number']:
                                                        filename_arr[j][7].insert(len(filename_arr[j][7]) - s, rtp['payload'])
                                                        filename_arr[j][10].insert(len(filename_arr[j][10]) - s, rtp['seq_number'])
                                                        filename_arr[j][11].insert(len(filename_arr[j][11]) - s, rtp['timestamp'])
                                                        logQ.put([processName,'error', 'insert rtp payload to existing stream, probably wrong sequence, insert backward position: %s, rtp seq: %s' % (s, rtp['seq_number'])])
                                                        break
                                                    if s == 3000:
                                                        logQ.put([processName,'error', 'tried to insert rtp payload to existing stream, but faild, last 3000 packets all inappropriate, rtp seq: %s' % rtp['seq_number']])
                                                        break
                                                else:
                                                    filename_arr[j][7].insert(0, rtp['payload'])
                                                    filename_arr[j][10].insert(0, rtp['seq_number'])
                                                    filename_arr[j][11].insert(0, rtp['timestamp'])
                                                    logQ.put([processName,'error', 'insert rtp payload to the most front, probably wrong sequence, rtp seq: %s', rtp['seq_number']])
                                            elif 0 < filename_arr[j][10][-1] + 65536 - rtp['seq_number'] < 3000:
                                                for s in range(len(filename_arr[j][10])):
                                                    if -3000 < filename_arr[j][10][-1 - s] - rtp['seq_number'] < 0:
                                                        filename_arr[j][7].insert(len(filename_arr[j][7]) - s, rtp['payload'])
                                                        filename_arr[j][10].insert(len(filename_arr[j][10]) - s, rtp['seq_number'])
                                                        filename_arr[j][11].insert(len(filename_arr[j][11]) - s, rtp['timestamp'])
                                                        logQ.put([processName,'error', 'insert rtp payload to existing stream, probably wrong sequence and roundback, insert backward position: %s, rtp seq: %s' % (s, rtp['seq_number'])])
                                                        break
                                                    if s == 3000:
                                                        logQ.put([processName,'error', 'tried to insert rtp payload to existing stream, but faild, last 3000 packets all inappropriate, rtp seq: %s' % rtp['seq_number']])
                                                        break
                                                else:
                                                    filename_arr[j][7].insert(0, rtp['payload'])
                                                    filename_arr[j][10].insert(0, rtp['seq_number'])
                                                    filename_arr[j][11].insert(0, rtp['timestamp'])
                                                    logQ.put([processName,'error', 'insert rtp payload to the most front, probably wrong sequence, rtp seq: %s' % rtp['seq_number']])
                                            globalSeq[j][3] = globalSeq[j][3] + 1
                                        existFlag=True
                                    j=j+1
                                if existFlag==False:
                                    filename_arr_count=filename_arr_count+1
                                    filename_arr.append([ip_addr_from, str(port1), ip_addr_to, str(port2), PacketTime, PacketTime, 1, [rtp['payload']], 'PT'+str(payload_type_num), rtp['SSRC'], [rtp['seq_number']], [rtp['timestamp']], 0])
                                    if level == 'debug':
                                        logQ.put([processName,'debug', 'create new member in steam array'])
                                    globalSeq.append([rtp['seq_number'], rtp['seq_number'], 0, 0])
                                    if rtp['seq_number'] == 65535:
                                        globalSeq[j][2] = globalSeq[j][2] + 1
                                    maxTimeDeltaList.append([0, rtp['seq_number']])
                            else:
                                j=0
                                while j<filename_arr_count:
                                    if filename_arr[j][0]==ip_addr_from and filename_arr[j][1]==str(port1) and filename_arr[j][2]==ip_addr_to and filename_arr[j][3]==str(port2) and filename_arr[j][8]=='PT'+str(payload_type_num) and filename_arr[j][9]==rtp['SSRC']:
                                        filename_arr[j][12] = filename_arr[j][12] + 1
                                        if level == 'debug':
                                            logQ.put([processName,'debug', 'recognized as duplicated, stream dup counter++ and discarding'])
                                    j=j+1

            iStartPos = iStartPos + packet_len + 16
            packet_num += 1
        for j in range(len(filename_arr)):
            filename_arr[j].append(globalSeq[j][1] - globalSeq[j][0] + 1 - filename_arr[j][6])
            filename_arr[j].append(globalSeq[j][3])
            filename_arr[j].append(str(round(maxTimeDeltaList[j][0],3)) + '/' + str(maxTimeDeltaList[j][1]))
        
        try:
            for pr in filename_arr:
                amrPayloadFile = NamedTemporaryFile(mode='wb', delete=False)
                pickle.dump(pr[7] , amrPayloadFile)
                pr[7] = amrPayloadFile.name
                amrPayloadFile.flush()
                amrPayloadFile.close()
                
                seqFile = NamedTemporaryFile(mode='wb', delete=False)
                pickle.dump(pr[10] , seqFile)
                pr[10] = seqFile.name
                seqFile.flush()
                seqFile.close()
                
                timeStampFile = NamedTemporaryFile(mode='wb', delete=False)
                pickle.dump(pr[11] , timeStampFile)
                pr[11] = timeStampFile.name
                timeStampFile.flush()
                timeStampFile.close()
        except Exception as e:
            pass
            logQ.put([processName,'error', 'NamedTemporaryFile IO error %s' % str(e)])
        refreshQ.put([pcapFileName, processName, 'finish', filename_arr])

def multiParsePcapProcessInit(q):
    print(q)
    multiParser.q = q
    
def multiParsePcapProcessLogger(parserThrState, logQueue, logger):
    logger.info('multiParsePcapProcessLogger thread normal start')
    while parserThrState.value:
        try:
            logData = logQueue.get(block = False)
            if logData[0] == 'info':
                logger.info(logData[0], logData[2])
            elif logData[0] == 'debug':
                logger.debug(logData[0], logData[2])
            elif logData[0] == 'error':
                logger.error(logData[0], logData[2])
            else:
                logger.error(logData)
        except queue.Empty:
            time.sleep(0.3)
            continue
        except Exception as e:
            logger.error('multiParsePcapProcessLogger thread unknown error', exc_info=True)
    logger.info('multiParsePcapProcessLogger thread normal exit')

class multiParsePcapThread(QtCore.QThread):
    def __init__(self, pcapFilePathList, loggerHandlerLevel):
        QtCore.QThread.__init__(self)
        self.pcapFilePathList = pcapFilePathList
        self.level = loggerHandlerLevel
        self.processingPcap = {}
        self.logger = logging.getLogger('parserThr')
        self.parserThrState = mp.Value('I', 0)
        self.refreshProcessQ = mp.Queue()
        self.logProcessQ = mp.Queue()
        self.jobProcessQ = mp.Queue()
        self.logger.info('multiParser thread initiated')
        self.subProcessList = []
        self.failList = []
        self.successList = []
        
    def stop(self):
        self.parserThrState.value = 0
        self.logger.info('multiParser thread get stop event')

    def run(self):
        global parseFailInfo
        global parseResult
        self.parserThrState.value = 1
        for i in range(len(self.pcapFilePathList)):
            self.jobProcessQ.put(self.pcapFilePathList[i])
        self.logThr = threading.Thread(target=multiParsePcapProcessLogger, args =(self.parserThrState, self.logProcessQ, self.logger))
        self.logThr.daemon = True
        self.logThr.start()
        for i in range(min(os.cpu_count(), len(self.pcapFilePathList))):
            p = mp.Process(target=multiParser, args=(self.parserThrState, self.jobProcessQ, self.refreshProcessQ, self.level, self.logProcessQ))
            self.subProcessList.append(p)
            p.daemon = True
            p.start()
        while self.parserThrState.value and self.pcapFilePathList:
            try:
                M = self.refreshProcessQ.get(block = False)   #M[0] fileName, M[1]processName, M[2]error, M[3]detailed error
                self.logger.debug('%s', str(M))
                if M[2] == 'process':
                    if  self.processingPcap.get(M[0]) != None:
                        self.processingPcap[M[0]][0] = M[3]
                    else:
                        self.logger.error('multiParser thread severe error: get feedback pcapFile no longer in processing list')
                    if len(self.processingPcap) > 1:
                        tempString = '  '.join(["{fileName}: {progress}%".format(fileName=self.processingPcap[i][1], progress = self.processingPcap[i][0]) for i in self.processingPcap])
                        self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), tempString)
                        self.logger.debug('multiParser thread update statusBar: %s', tempString)
                    else:
                        self.emit(QtCore.SIGNAL('refreshProgressBar(QString, int)'), self.processingPcap[M[0]][1], M[3])
                        self.logger.debug('multiParser thread update statusBar: %s, %s', self.processingPcap[M[0]][1], M[3])
                elif M[2] == 'start':
                    self.processingPcap[M[0]] = [0, os.path.basename(M[0])]
                    self.logger.info('job dispatched: %s, %s, %s', M[0], M[1], M[3])
                elif M[2] == 'finish':
                    self.successList.append(M[0])
                    if not parseResult:
                        parseResult = []
                    parseResult.extend(M[3])
                    self.pcapFilePathList.remove(M[0])
                    del self.processingPcap[M[0]]
                    self.emit(QtCore.SIGNAL('refreshTableWidget()'))
                    self.logger.info('job done: %s, %s, %s', M[0], M[1], str(datetime.datetime.now()))
                elif M[2] == 'error':
                    try:
                        self.failList.append(M[0])
                        self.pcapFilePathList.remove(M[0])
                        del self.processingPcap[M[0]]
                    except (ValueError, KeyError) as e:
                        self.logger.error('error when del or remove, race condition')
                    except Exception as e:
                        self.logger.error('unknown error', exc_info=True)

            except queue.Empty:
                time.sleep(0.01)
            except Exception as e:
                self.logger.error('multiParser thread feedback get error', exc_info=True)
        
        self.logger.info('multiParser thread normally exited')
        self.logger.debug('multiParser thread normal finished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        if len(self.failList) > 0:
            tempStr = '%s files parsed and imported, %s files failed parsing' % (len(self.successList), len(self.failList))
        else:
            tempStr = '%s files parsed and imported' % len(self.successList)
        self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), tempStr)
        self.parserThrState.value = 0

class MatplotlibWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        super(MatplotlibWidget, self).__init__(parent)
        self.figure = Figure(facecolor='white')
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas.setParent(self)
        self.axis = self.figure.add_subplot(111)
        self.ax2 = self.axis.twiny()
        self.ax2.set_xlim(self.axis.get_xlim())
        self.logger = logging.getLogger('MainThrd')
        self.layoutVertical = QtGui.QVBoxLayout(self)
        self.layoutVertical.addWidget(self.canvas)
        self.figure.subplots_adjust(left=0.05, bottom=0.1, top=0.85, right=0.95, wspace = 0, hspace = 0)
        self.position = 0
        self.background = None
        self.line = None
        self.line1 = None
        self.legend = None
        self.step = 500  # 100ms

    def resizeEvent(self, event):
        event.accept()
        self.emit(QtCore.SIGNAL('updateProgressLineSize()'))
    
class progressLine(QtGui.QWidget):
    def __init__(self, parent=None):
        super(progressLine, self).__init__(parent)
        palette = QtGui.QPalette(self.palette())
        palette.setColor(palette.Background, QtCore.Qt.transparent)
        self.setPalette(palette)
        self.parentWidth = screenWidth # 1680
        self.outerMargin = 9
        self.plotXMargin = 0.05
        self.xPercentage = 0
        self.plotStartPosition = (self.parentWidth - 2 * self.outerMargin) * self.plotXMargin + self.outerMargin
        self.plotWidth = self.parentWidth - self.outerMargin * 2 - self.plotStartPosition * 2 + 2
        self.xposition = self.plotWidth * self.xPercentage + self.plotStartPosition
        self.mouseClickEvent = False
        self.setMouseTracking(True)
        self.Duration = 0
        self.startTime = datetime.datetime.fromtimestamp(0)
        self.logger = logging.getLogger('MainThrd')
        self.logger.info('progressLine initiate, parentWidth: %s, selfWidth: %s, plotWidth: %s ,startPos: %s, initial pos: %s', self.parentWidth, self.width(), self.plotWidth, self.plotStartPosition, self.xposition)
        
    def paintEvent(self, event):
        if not self.mouseClickEvent:
            self.plotStartPosition = (self.parentWidth - 2 * self.outerMargin) * self.plotXMargin + self.outerMargin
            self.plotWidth = self.parentWidth - self.outerMargin * 2 - self.plotStartPosition * 2 + 2
            self.xposition = self.plotWidth * self.xPercentage + self.plotStartPosition
        painter = QtGui.QPainter()
        painter.begin(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.fillRect(event.rect(), QtGui.QBrush(QtGui.QColor(255, 255, 255, 0)))
        painter.drawLine(self.xposition, self.height() * 0, self.xposition, self.height() * 1)
        painter.setPen(QtGui.QPen(QtCore.Qt.NoPen))
        self.mouseClickEvent = False
        self.logger.debug('audio Play progressLine moving to pos: %s, pos ratio: %s', self.xposition, self.xPercentage)
        self.logger.debug('progressLine initiate, parentWidth: %s, selfWidth: %s, plotWidth: %s ,startPos: %s, currentPos: %s', self.parentWidth, self.width(), self.plotWidth, self.plotStartPosition, self.xposition)
        
    def mousePressEvent(self, QMouseEvent):
        self.xposition = QMouseEvent.pos().x()
        self.xPercentage = (self.xposition - self.plotStartPosition)/self.plotWidth
        self.mouseClickEvent = True
        self.update()
        self.logger.info('audio Play progressLine Mouse click event, click pos: %s, pos ratio: %s', QMouseEvent.pos(), self.xPercentage)
        self.emit(QtCore.SIGNAL('updatePcmPlayRatio(float)'), self.xPercentage)
        
    def mouseReleaseEvent(self, event):
        self.xposition = self.mapFromGlobal(event.globalPos()).x()
        self.xPercentage = (self.xposition - self.plotStartPosition)/self.plotWidth
        if 0 <= self.xPercentage <= 1:
            absoluteTime = self.Duration * self.xPercentage
            referenceTime = self.startTime + datetime.timedelta(seconds = absoluteTime)
            QtGui.QToolTip.showText(event.globalPos(), str(round(absoluteTime, 3)) + 's / ' + referenceTime.strftime("%H:%M:%S.%f"), self)
            
    def mouseMoveEvent(self, event):
        xposition = self.mapFromGlobal(event.globalPos()).x()
        xPercentage = (xposition - self.plotStartPosition)/self.plotWidth
        if 0 <= xPercentage <= 1:
            absoluteTime = self.Duration * xPercentage
            referenceTime = self.startTime + datetime.timedelta(seconds = absoluteTime)
            QtGui.QToolTip.showText(event.globalPos(), str(round(absoluteTime, 3)) + 's / ' + referenceTime.strftime("%H:%M:%S.%f"), self)

class ParsePcapApp(QtGui.QMainWindow, pcapParseUi.Ui_MainWindow):
    def __init__(self):
        super(self.__class__, self).__init__()
        setup_logging()
        self.logger = logging.getLogger('MainThrd')
        self.logger.info('pcapParseGui MainThread initiated')
        self.setupUi(self)
        self.actionPick_a_Pcap_File.triggered.connect(self.browse_pcap_file)
        self.actionPlot_Selected_Stream.triggered.connect(self.plotPcm)
        self.actionExport_Selected_Line.triggered.connect(self.exportPcm)
        self.actionExit.triggered.connect(self.closeEvent)
        self.actionPlay_2.triggered.connect(self.playPcm)
        self.actionStop.triggered.connect(self.stopPlayPcm)
        self.actionDebug.triggered.connect(self.checkDebug)
        self.actionInfo.triggered.connect(self.checkInfo)
        self.actionClear.triggered.connect(self.ClearAll)
        self.matplotlibWidget = MatplotlibWidget(self)
        self.splitter.addWidget(self.matplotlibWidget)
        self.progressbar = QtGui.QProgressBar()
        self.statusbar.addWidget(self.progressbar)
        self.lastPcapFilePath = sys.path[0]
        self.openFilter = 'Pcap Files(*.pcap)'
        self.saveFilePath = sys.path[0]
        self.lastWindowTitle = mainTitle

        ptTemp = []
        self.ptDict = {}
        try:
            if os.path.exists(r'pt.cfg'):
                ptTemp = open(r'pt.cfg', 'r').read().split('\n')
            for pt in ptTemp:
                if pt[:2] != '//':
                    ptList = pt.strip().split(' ')
                    if 96<=int(ptList[0])<=127 and  ptList[-1] in availableAmrOpt:
                        self.ptDict[pt.strip().split(' ')[0]] = pt.strip().split(' ')[-1]
        except Exception as e:
            self.logger.error('Loading pt.cfg file error:', exc_info=True)
        try:
            if os.path.exists(r'DATA'):
                with open('DATA', 'rb') as f:
                    data = pickle.load(f)
                    if os.path.exists(data['lastPcapFilePath']):
                        self.lastPcapFilePath = data['lastPcapFilePath']
        except Exception as e:
            self.logger.error('Loading DATA file error:', exc_info=True)
        self.connect(QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key_Escape), self), QtCore.SIGNAL('activated()'), self.cancelEvent)
        self.progressLine = progressLine(self.matplotlibWidget)
        self.progressLine.hide()
        self.clip = QtGui.QApplication.clipboard()
        self.initVarConfig()
        self.logger.debug('gc.get_count: %s', gc.get_count())
        self.logger.debug('gc.get_threshold: %s', gc.get_threshold())
		
    def initVarConfig(self):
        global parseResult
        global pcmList
        global parseFailInfo
        parseResult, pcmList, parseFailInfo = None, None, None
        self.splitter.setSizes([self.height()//2, self.height()//2])
        self.matplotlibWidget.hide()
        self.setWindowTitle(mainTitle)
        self.progressbar.hide()
        self.progressbar.setMaximum(100)
        self.pcmPlayStartP = 0
        self.actionPlot_Selected_Stream.setEnabled(False)
        self.actionExport_Selected_Line.setEnabled(False)
        self.actionPlay_2.setEnabled(False)
        self.actionStop.setEnabled(False)
        self.parseThread = None
        self.decodeThread = None
        self.comboboxList = []
        self.currentPlotting = None
        self.currentExporting = None
        self.currentPlotted = None
        self.listenerThr1 = None
        self.ffmpegWrapThr = None
        self.pcapFileName = ''
        self.loggerHandlerLevel = 'info'
        

    def keyPressEvent(self, e):
        if (e.modifiers() & QtCore.Qt.ControlModifier):
            selected = self.tableWidget.selectedRanges()

            if e.key() == QtCore.Qt.Key_C: #copy
                s = ""

                for r in range(selected[0].topRow(), selected[0].bottomRow()+1):
                    for c in range(selected[0].leftColumn(), selected[0].rightColumn()+1):
                        try:
                            if c == 9:
                                s += str(self.comboboxList[r].currentText()) + "\t"
                            else:
                                s += str(self.tableWidget.item(r,c).text()) + "\t"
                        except AttributeError:
                            s += "\t"
                    s = s[:-1] + "\n"
                self.clip.setText(s)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()
    
    def dropEvent(self, event):
        filePathList = [url.toLocalFile() for url in event.mimeData().urls()]
        self.logger.info('user drop file list: %s', filePathList)
        self.browse_pcap_file(filePathList)

    def refreshProgressBar(self, file = None, val = None):
        self.progressbar.show()
        if val == None:
            val = self.progressbar.value() + 1
            self.progressbar.setFormat('%s%%' % val)
        else:
            self.progressbar.setFormat('%s: %s%%' % (file, val))
        self.progressbar.setValue(val)


    def refreshMatplotLine(self, percentage):
        if self.listenerThr1 == None or self.listenerThr1.state != 1:
            return
        if percentage < 0 or percentage > 1:
            self.logger.info('change bigger than 1 percentage value to 1, original value from pcmPlayer Thr: %s', percentage)
            percentage = 1
        self.progressLine.xPercentage = percentage
        self.progressLine.update()

    def updatePcmPlayRatio(self, percentage):
        global pcmList
        ind = int(percentage * pcmList[self.currentPlotted][4])
        if ind%2 == 1:
            ind = ind - 1
        if self.listenerThr1 != None and self.listenerThr1.isRunning():
            self.listenerThr1.positionInd.value = ind
        self.pcmPlayStartP = ind

    def updateProgressLineSize(self):
        self.progressLine.resize(self.matplotlibWidget.size())
        
    def browse_pcap_file(self, pcapFilePathList = None):
        global parseFailInfo
        if not pcapFilePathList:
            pcapFilePathList, self.openFilter = QtGui.QFileDialog.getOpenFileNamesAndFilter(self,'Pick a Pcap File',self.lastPcapFilePath,'Pcap Files(*.pcap);;all files(*.*)',self.openFilter)
        if not pcapFilePathList:
            return
        self.statusBar().clearMessage()
        self.pcapFileName = '&&'.join(pcapFilePathList)
        self.lastPcapFilePath = os.path.dirname(pcapFilePathList[0])
        self.parseThread = multiParsePcapThread(pcapFilePathList, self.loggerHandlerLevel)
        self.connect(self.parseThread, QtCore.SIGNAL("refreshTableWidget()"), self.refreshTableWidget)
        self.connect(self.parseThread, QtCore.SIGNAL("subThrUpdateStatusbar(QString)"), self.subThrUpdateStatusbar)
        self.connect(self.parseThread, QtCore.SIGNAL("refreshProgressBar(QString, int)"), self.refreshProgressBar)
        self.connect(self.parseThread, QtCore.SIGNAL("finished()"), self.multiParseFinished)
        parseFailInfo = ''
        self.parseThread.start()
        self.actionPick_a_Pcap_File.setEnabled(False)
        self.actionPlot_Selected_Stream.setEnabled(False)
        self.actionExport_Selected_Line.setEnabled(False)
        self.lastWindowTitle = self.windowTitle()
        self.setWindowTitle(mainTitle + str(self.pcapFileName))
        try:
            with open('DATA', 'wb') as f:
                data = {
                    'lastPcapFilePath': self.lastPcapFilePath
                    }
                pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            self.logger.error('writing DATA file error:', exc_info=True)

    def refreshTableWidget(self):
        global parseResult
        global pcmList
        self.logger.info('current num of rows: %s, num of parseResult: %s', self.tableWidget.rowCount(), len(parseResult))
        tempRowCount = self.tableWidget.rowCount()
        if len(parseResult) > self.tableWidget.rowCount():
            self.tableWidget.setRowCount(len(parseResult))
        else:
            self.logger.error('num of parseResult was supposed to be bigger than current num of rows')
            return
        if not self.comboboxList:
            self.comboboxList = []
            pcmList = []
            self.tableWidget.setColumnCount(len(tableHeaders))
            self.tableWidget.setHorizontalHeaderLabels(tableHeaders)
        for i in range(tempRowCount, len(parseResult)):
            combobox = QtGui.QComboBox()
            for item in availableAmrOpt:
                combobox.addItem(item)
            self.comboboxList.append(combobox)
            pcmList.append([None, 8000, None, None, None])
        for row in range(tempRowCount, len(parseResult)):
            for column in range(7):
                itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][column]))
                itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
                if column == 1 or column == 3 or column == 6:
                    itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
                else:
                    itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft)
                self.tableWidget.setItem(row,column, itemTemp)
            itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][8]))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft)
            self.tableWidget.setItem(row,7, itemTemp)
		
            itemTemp = QtGui.QTableWidgetItem(parseResult[row][9].decode('utf8'))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft)
            self.tableWidget.setItem(row,8, itemTemp)
		
            self.tableWidget.setCellWidget(row, 9, self.comboboxList[row])
            ptInDict = self.ptDict.get(parseResult[row][8][2:])
            if ptInDict:
                self.comboboxList[row].setCurrentIndex(self.comboboxList[row].findText(ptInDict))
            itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][13]))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
            self.tableWidget.setItem(row, 10, itemTemp)  # lost
		
            itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][12]))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
            self.tableWidget.setItem(row, 11,  itemTemp)  # dup
		
            itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][14]))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
            self.tableWidget.setItem(row, 12, itemTemp)  # wrongSeq
		
            itemTemp = QtGui.QTableWidgetItem(str(parseResult[row][15]))
            itemTemp.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            itemTemp.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
            self.tableWidget.setItem(row, 13, itemTemp)  # maxDelta

        self.tableWidget.resizeColumnsToContents()
        self.tableWidget.update()
        # QtGui.QApplication.processEvents()

    def multiParseFinished(self):
        self.decodeThread = None
        self.parseThread = None
        self.progressbar.hide()
        self.actionPick_a_Pcap_File.setEnabled(True)
        self.actionPlot_Selected_Stream.setEnabled(True)
        self.actionExport_Selected_Line.setEnabled(True)
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        n = gc.collect()
        self.logger.debug('number of unreachable objects: %s', n)
        self.logger.debug('parse Finished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def pcmDecode(self, index):
        global decodeInfo
        decodeInfo = ''
        self.statusBar().showMessage('')
        self.progressbar.setValue(0)
        self.progressbar.show()
        jobTypeList = [str(self.comboboxList[index].currentText())]
        self.decodeThread = multiDecoderThread([index], jobTypeList, self.loggerHandlerLevel, self.actionFast_Decode.isChecked())
        self.connect(self.decodeThread, QtCore.SIGNAL("refreshProgressBar(QString, int)"), self.refreshProgressBar)
        self.connect(self.decodeThread, QtCore.SIGNAL("finished()"), self.decodeFinished)
        self.decodeThread.start()
        self.actionPick_a_Pcap_File.setEnabled(False)
        self.actionPlot_Selected_Stream.setEnabled(False)
        self.actionExport_Selected_Line.setEnabled(False)
        self.actionClear.setEnabled(False)

    def decodeFinished(self):
        global decodeInfo
        global pcmList
        self.progressbar.setValue(100)
        if self.currentPlotting != None:
            index = self.currentPlotting
            if pcmList[index][0]:
                if str(self.comboboxList[index].currentText()) == 'h264':
                    pass
                else:
                    if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                        self.listenerThr1.stop()
                    self.plotWithData(index)
                    self.logger.info('decode finished, main thread start plotting for index %s', index)
            else:
                if decodeInfo != 'decode cancelled':
                    decodeInfo = decodeInfo + '  NOTHING to plot or export!!!'
                    self.logger.error('severe decode error!')
            self.currentPlotting = None
            
        elif self.currentExporting != None:
            index = self.currentExporting
            if pcmList[index][0]:
                self.saveAvFile(index)
                self.logger.info('decode finished, main thread start exporting for index %s', index)
            else:
                if decodeInfo != 'decode cancelled':
                    decodeInfo = decodeInfo + '  NOTHING to plot or export!!!'
                    self.logger.error('severe decode error!')
            self.currentExporting = None
        self.progressbar.hide()
        self.actionPick_a_Pcap_File.setEnabled(True)
        self.actionPlot_Selected_Stream.setEnabled(True)
        self.actionExport_Selected_Line.setEnabled(True)
        self.actionClear.setEnabled(True)
        if decodeInfo:
            self.statusBar().showMessage(decodeInfo)
            self.logger.info('decode error summary: %s', decodeInfo)
        self.decodeThread = None
        n = gc.collect()
        self.logger.debug('number of unreachable objects: %s', n)
        self.logger.debug('decodeFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def plotWithData(self, index):
        self.matplotlibWidget.axis.cla()
        self.matplotlibWidget.ax2.cla()
        if self.matplotlibWidget.legend:
            self.matplotlibWidget.legend.remove()
        global parseResult
        try:
            with open(pcmList[index][0], 'rb') as temp:
                data = np.fromstring(temp.read(), dtype=np.short)
        except Exception as e:
            self.logger.error('IO error while open cache for plotting', exc_info=True)
            self.statusBar().showMessage('severe error! failed to open pcm cache file')
            return
        t = np.arange(0, len(data)/pcmList[index][1], 1.0/pcmList[index][1])
        xlim = len(data)/pcmList[index][1]
        self.progressLine.Duration = len(data)/pcmList[index][1]
        if len(data) > screenWidth * 100:
            tempIndex = list(filter(lambda x: x % (len(data) // (screenWidth * 100)) == 0, range(len(data))))
            data = [data[i] for i in tempIndex]
            t = [t[i] for i in tempIndex]
        self.matplotlibWidget.axis.set_xlim([0, xlim])
        self.matplotlibWidget.axis.set_xlabel("reference time")
        self.matplotlibWidget.ax2.set_xlabel("absolute time")
        self.matplotlibWidget.axis.set_ylabel("amplitude")
        self.matplotlibWidget.axis.set_title("Time Domain Plotting", y = 1.1)
        try:
            line1 = self.matplotlibWidget.axis.plot(t, data, color='black')
        except MemoryError:
            self.logger.error('MemoryError while plotting with plotWithData')
            self.statusBar().showMessage('MemoryError while plotting')
        except Exception as e:
            self.logger.error('unexpected error while plotting with plotWithData', exc_info=True)
            self.statusBar().showMessage('unexpected error, check log for details')
        self.matplotlibWidget.axis.grid(True,'major')
        self.matplotlibWidget.legend = self.matplotlibWidget.figure.legend( line1, ['index:' + str(index+1) + ' ' + '_'.join(parseResult[index][:4])], loc='upper right', fontsize = 10, frameon = True)
        new_tick_locations = np.array([0.0, .2, .4, .6, .8, 1.0])
        dt1 = datetime.datetime.strptime(pcmList[index][2], "%Y-%m-%d %H:%M:%S.%f")
        self.matplotlibWidget.ax2.set_xticks(new_tick_locations)
        self.matplotlibWidget.ax2.set_xticklabels([(dt1 + datetime.timedelta(seconds = self.matplotlibWidget.axis.get_xlim()[1] * i)).strftime("%H:%M:%S.%f") for i in new_tick_locations])
        self.matplotlibWidget.canvas.draw()
        self.matplotlibWidget.show()
        self.progressLine.xPercentage = 0
        self.progressLine.update()
        self.progressLine.startTime = dt1
        self.progressLine.setVisible(True)
        self.pcmPlayStartP = 0
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        self.currentPlotted = index
        self.connect(self.progressLine, QtCore.SIGNAL("updatePcmPlayRatio(float)"), self.updatePcmPlayRatio)
        self.connect(self.matplotlibWidget, QtCore.SIGNAL("updateProgressLineSize()"), self.updateProgressLineSize)
        
    def resizeEvent(self, event):
        event.accept()
        self.progressLine.resize(self.matplotlibWidget.size())
        self.progressLine.parentWidth = self.width()
        self.progressLine.update()

    
    def plotPcm(self):
        self.logger.info('selected rows: %s', [i.row() for i in self.tableWidget.selectionModel().selectedRows()])
        if self.tableWidget.currentItem() == None:
            return
        index = self.tableWidget.currentItem().row()
        if str(self.comboboxList[index].currentText()) == 'h264':
            self.statusBar().showMessage('can not plot h264 video format!')
        else:
            global pcmList
            if index != None:
                self.statusBar().showMessage('')
                if not pcmList[index][0] or pcmList[index][3] != str(self.comboboxList[index].currentText()):
                    if pcmList[index][0]:
                        try:
                            os.unlink(pcmList[index][0])
                        except FileNotFoundError:
                            self.logger.error('no such file while deleting cache %s', pcmList[index][0])
                        except Exception as e:
                            self.logger.error('unexpected error while deleting cache', exc_info=True)
                    pcmList[index][0] = None
                    pcmList[index][3] = str(self.comboboxList[index].currentText())
                    self.currentPlotting = index
                    self.pcmDecode(index)
                elif pcmList[index][0] and pcmList[index][3] == str(self.comboboxList[index].currentText()):
                    if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                        self.listenerThr1.stop()
                    self.plotWithData(index)

                else:
                    self.logger.error('severe decode error!')

    def exportPcm(self):
        global pcmList
        global parseResult
        selectedRowIndex = [i.row() for i in self.tableWidget.selectionModel().selectedRows()]
        self.logger.info('selected rows: %s', selectedRowIndex)
        if len(selectedRowIndex) == 1:
            index = selectedRowIndex[0]
            if index != None:
                if not pcmList[index][0] or pcmList[index][3] != str(self.comboboxList[index].currentText()):
                    if pcmList[index][0]:
                        try:
                            os.unlink(pcmList[index][0])
                        except FileNotFoundError:
                            self.logger.error('no such file while deleting cache %s', pcmList[index][0])
                        except Exception as e:
                            self.logger.error('unexpected error while deleting cache', exc_info=True)
                    self.currentExporting = index
                    pcmList[index][0] = None
                    pcmList[index][3] = str(self.comboboxList[index].currentText())
                    self.pcmDecode(index)
                    self.logger.info('decoding index %s before exporting', index)
                elif pcmList[index][0] and pcmList[index][3] == str(self.comboboxList[index].currentText()):
                    self.logger.info('export index %s with in-place data', index)
                    self.saveAvFile(index)
                else:
                    self.logger.critical('severe unknown error!')
        elif len(selectedRowIndex) > 1:
            dir = QtGui.QFileDialog.getExistingDirectory(self, "Select export folder:", self.saveFilePath, QtGui.QFileDialog.ShowDirsOnly)
            if not dir:
                return
            self.saveFilePath = dir
            jobList = mp.Queue()
            exportedIndexList = []
            for i in selectedRowIndex:
                if not pcmList[i][0] or pcmList[i][3] != str(self.comboboxList[i].currentText()):
                    jobList.put([i, str(self.comboboxList[i].currentText()), parseResult[i][7], parseResult[i][10], parseResult[i][11]])
                elif pcmList[i][0] and pcmList[i][3] == str(self.comboboxList[i].currentText()):
                    shutil.copyfile(pcmList[i][0], os.path.join(dir, 'index' + str(i + 1) + '_' + ('_'.join(parseResult[i][:4])).replace(':',' ')))
                    exportedIndexList.append(i)
                else:
                    self.logger.critical('severe unknown error!')
            if jobList.qsize() != 0:
                self.statusBar().showMessage('for multi selection export, can only export already decoded ones')
                        
    def playPcm(self):
        self.logger.debug('mainThr start playPcm, thread count: %s, thread enumerating: %s', threading.activeCount(), [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())
        if self.currentPlotted != None:
            if self.listenerThr1 == None or self.listenerThr1.isRunning() == False:
                global pcmList
                if pcmList[self.currentPlotted][0]:
                    try:
                        mediaData = open(pcmList[self.currentPlotted][0], 'rb').read()
                    except Exception as e:
                        self.logger.error('IO error while open cache for playing', exc_info=True)
                    self.listenerThr1 = pcmPlayer(mediaData, self.pcmPlayStartP, pcmList[self.currentPlotted][1])
                    self.connect(self.listenerThr1, QtCore.SIGNAL("refreshMatplotLine(float)"), self.refreshMatplotLine)
                    self.connect(self.listenerThr1, QtCore.SIGNAL("finished()"), self.playPcmFinished)
                    self.listenerThr1.start()
                    if not(self.decodeThread and self.decodeThread.isRunning() or self.parseThread and self.parseThread.isRunning):
                        self.statusBar().showMessage('playing')
            else:
                if self.listenerThr1.state == 1:
                    if not(self.decodeThread and self.decodeThread.isRunning() or self.parseThread and self.parseThread.isRunning):
                        self.statusBar().showMessage('paused')
                elif self.listenerThr1.state == 2:
                    if not(self.decodeThread and self.decodeThread.isRunning() or self.parseThread and self.parseThread.isRunning):
                        self.statusBar().showMessage('playing')
                self.listenerThr1.swapState()

    def stopPlayPcm(self):
        if self.listenerThr1 and self.listenerThr1.isRunning():
            self.listenerThr1.stop()
            self.listenerThr1 == None

    def playPcmFinished(self):
        self.pcmPlayStartP = 0
        if not(self.decodeThread and self.decodeThread.isRunning() or self.parseThread and self.parseThread.isRunning):  # in case status bar not show progress bar
            self.statusBar().showMessage('playing stopped!')
        self.listenerThr1 = None
        self.logger.debug('playFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())
        n = gc.collect()
        self.logger.debug('number of unreachable objects: %s', n)

    def checkDebug(self):
        self.actionDebug.setChecked(True)
        self.actionInfo.setChecked(False)
        self.logger.handlers[0].setLevel(logging.DEBUG)
        self.loggerHandlerLevel = 'debug'

    def checkInfo(self):
        self.actionDebug.setChecked(False)
        self.actionInfo.setChecked(True)
        self.logger.handlers[0].setLevel(logging.INFO)
        self.loggerHandlerLevel = 'info'

    def clearCache(self):
        global pcmList
        if pcmList:
            for mediaFile in pcmList:
                if mediaFile[0]:
                    try:
                        os.unlink(mediaFile[0])
                        self.logger.debug('deleting %s before exit', mediaFile[0])
                    except Exception as e:
                        self.logger.error('IO error while deleting cache', exc_info=True)

        global parseResult
        if parseResult:
            for pr in parseResult:
                try:
                    if pr[7]:
                        os.unlink(pr[7])
                        self.logger.debug('deleting %s before exit', pr[7])
                    if pr[10]:
                        os.unlink(pr[10])
                        self.logger.debug('deleting %s before exit', pr[10])
                    if pr[11]:
                        os.unlink(pr[11])
                        self.logger.debug('deleting %s before exit', pr[11])
                except Exception as e:
                    self.logger.error('IO error while deleting cache', exc_info=True)

    def ClearAll(self):
        if not parseFailInfo and parseResult:
            if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                self.listenerThr1.stop()
                self.logger.info('pcm player thread force terminated!')
        self.clearCache()
        self.initVarConfig()
        self.tableWidget.setColumnCount(len(tableHeaders))
        self.tableWidget.setRowCount(0)
        self.tableWidget.setHorizontalHeaderLabels(tableHeaders)

        self.matplotlibWidget.axis.cla()
        self.matplotlibWidget.ax2.cla()
        if self.matplotlibWidget.legend:
            self.matplotlibWidget.legend.remove()
        self.matplotlibWidget.hide()

        n = gc.collect()
        self.logger.debug('number of unreachable objects: %s', n)
        self.logger.debug('parseFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())
    
    def closeEvent(self, event):
        quit_msg = "Sure To Exit?"
        reply = QtGui.QMessageBox.question(self, 'Message', quit_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                self.listenerThr1.stop()

            if self.ffmpegWrapThr !=None and self.ffmpegWrapThr.isRunning() ==True:
                self.ffmpegWrapThr.saveExit()

            self.clearCache()
            self.logger.info('pcapParseGui MainThread normal exiting')
            QtGui.QApplication.quit()
        else:
            event.ignore()

    def saveAvFile(self, index):
        if str(self.comboboxList[index].currentText()) == 'h264':
            if os.path.exists(r'ffmpeg.exe'):
                file_path, filter =  QtGui.QFileDialog.getSaveFileNameAndFilter(self,"save h264 file", os.path.join(self.saveFilePath, ('_'.join(parseResult[index][:4])).replace(':',' ')), "h264 files (*.h264);;mp4 file(*.mp4);;all files(*.*)")
            else:
                file_path, filter =  QtGui.QFileDialog.getSaveFileNameAndFilter(self,"save h264 file", os.path.join(self.saveFilePath, ('_'.join(parseResult[index][:4])).replace(':',' ')), "h264 files (*.h264);;all files(*.*)")
            if file_path:
                self.saveFilePath = os.path.dirname(file_path)
                if filter == 'mp4 file(*.mp4)':
                    try:
                        self.ffmpegWrapThr = ffmpegWrapThr(index, file_path)
                        self.connect(self.ffmpegWrapThr, QtCore.SIGNAL("subThrUpdateStatusbar(QString)"), self.subThrUpdateStatusbar)
                        self.connect(self.ffmpegWrapThr, QtCore.SIGNAL("finished()"), self.ffmpegConvertThrFinish)
                        self.ffmpegWrapThr.start()
                        self.actionPick_a_Pcap_File.setEnabled(False)
                        self.actionPlot_Selected_Stream.setEnabled(False)
                        self.actionExport_Selected_Line.setEnabled(False)
                        self.actionPlay_2.setEnabled(False)
                        self.actionStop.setEnabled(False)
                    except Exception as e:
                        self.logger.error('export to mp4 file failed:', exc_info=True)
                        self.statusBar().showMessage('export to mp4 file failed')
                else:
                    try:
                        shutil.copyfile(pcmList[index][0], file_path)
                        self.statusBar().showMessage('exported index ' + str(index+1) + ' using raw h264 format to ' + str(file_path))
                        self.logger.info('exported index %s using raw h264 format to %s', index, file_path)
                    except Exception as e:
                        self.logger.error('export to h264 file failed:', exc_info=True)
                        self.statusBar().showMessage('export to h264 file failed')
        else:
            file_path, filter =  QtGui.QFileDialog.getSaveFileNameAndFilter(self,"save pcm file", os.path.join(self.saveFilePath, ('_'.join(parseResult[index][:4])).replace(':',' ')), "pcm files (*.pcm);;wav files (*.wav);;all files(*.*)")
            if file_path:
                self.saveFilePath = os.path.dirname(file_path)
                try:
                    if filter == 'wav files (*.wav)':
                        wf = wave.open(file_path, 'wb')
                        wf.setnchannels(1)
                        wf.setsampwidth(2)
                        wf.setframerate(pcmList[index][1])
                        wf.writeframes(open(pcmList[index][0], 'rb').read())
                        wf.close()
                        self.statusBar().showMessage('exported index ' + str(index+1) + ' using wave format to ' + str(file_path))
                        self.logger.info('exported index %s using wave format to %s', index, file_path)
                    else:
                        shutil.copyfile(pcmList[index][0], file_path)
                        self.statusBar().showMessage('exported index ' + str(index+1) + ' using pcm format to ' + str(file_path))
                        self.logger.info('exported index %s using pcm format to %s', index, file_path)
                except Exception as e:
                    self.logger.error('save audio file failed:', exc_info=True)
                    self.statusBar().showMessage('export to file failed')

    def cancelEvent(self):
        if self.parseThread and self.parseThread.isRunning():
            self.parseThread.stop()
            self.setWindowTitle(self.lastWindowTitle)
        if self.decodeThread and self.decodeThread.isRunning():
            self.decodeThread.stop()
        if self.ffmpegWrapThr and self.ffmpegWrapThr.isRunning():
            self.ffmpegWrapThr.saveExit()

    def subThrUpdateStatusbar(self, msg):
        self.statusBar().showMessage(msg)
        
    def ffmpegConvertThrFinish(self):
        self.ffmpegWrapThr = None
        self.actionPick_a_Pcap_File.setEnabled(True)
        self.actionPlot_Selected_Stream.setEnabled(True)
        self.actionExport_Selected_Line.setEnabled(True)
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        self.logger.info('main thread get ffmpegWrapThr normal end event')
        n = gc.collect()
        self.logger.debug('number of unreachable objects: %s', n)

class ffmpegWrapThr(QtCore.QThread):
    def __init__(self, index, file_path):
        QtCore.QThread.__init__(self)
        self.index = index
        self.file_path = file_path
        self.logger = logging.getLogger('MainThrd')
        self.logger.info('ffmpegWrapThr initiated')
        self.p = None
        self.cancelled = False

    def run(self):
        global pcmList
        try:
            output = NamedTemporaryFile(mode="rb", delete=False)
            conversion_command = "ffmpeg -y -i " + pcmList[self.index][0] + " -vcodec h264 -f mp4 " + output.name
            self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'converting raw h264 to mp4!')
            self.logger.info('ffmpeg command: %s', conversion_command)
            self.p = subprocess.Popen(conversion_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p_out, p_err = self.p.communicate()
            if self.cancelled == False:
                if self.p.returncode == 0:
                    shutil.copyfile(output.name, self.file_path)
                    self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'exported index ' + str(self.index + 1) + ' using mp4 format to ' + str(self.file_path))
                else:
                    self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'exported index ' + str(self.index + 1) + ' using mp4 format failed, try raw h264 format')
                    self.logger.error('ffmpeg error, code: %s, error: %s', self.p.returncode, p_err)
            self.logger.info('ffmpegWrapThr normal end')
            self.p = None
            output.close()
            os.unlink(output.name)
        except Exception as e:
            if self.p:
                self.logger.info('ffmpegWrapThr terminating subprocess')
                self.p.terminate()
            self.logger.error('ffmpegWrapThr get error', exc_info=True)

    def saveExit(self):
        self.cancelled = True
        if self.p:
            self.p.terminate()
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'exporting mp4 file cancelled')
        self.logger.info('ffmpegWrapThr saveExit')

def main():
    app = QtGui.QApplication(sys.argv)
    mainForm = ParsePcapApp()
    mainForm.show()
    app.exec_()

if __name__ == '__main__':
    main()

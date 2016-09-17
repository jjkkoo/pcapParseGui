from PyQt4 import QtGui, QtCore
import pcapParseUi
import queue
import sys
import os
import shutil
import subprocess
# import copy
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
import multiprocessing
from multiprocessing import Process, Value, Array, Queue, Lock, Manager, cpu_count
from tempfile import TemporaryFile, NamedTemporaryFile

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

# sys.setcheckinterval = 20

def processPlayPcm(q, pcmRate, pcmData, playState, positionInd, logQueue):
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=pcmRate, output=True)
    playPosition = visagePosition = positionInd.value
    # updatePlotCount = 0
    # pcmPlayProcessLogger = logging.getLogger('pcmPlayProcess')
    # pcmPlayProcessLogger.info('pcmRate: %s, startPosition: %s', pcmRate, positionInd.value)
    logQueue.put(['info', 'pcmRate: %s, startPosition: %s' % (pcmRate, positionInd.value)])
    """
    while playPosition < len(pcmData) and os.getppid():
        stream.write(pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])
        playPosition = playPosition + 2 * int(pcmRate * STEP)
    """
    while playPosition < len(pcmData) and os.getppid():
        if visagePosition == positionInd.value:
            pass
        else:
            playPosition = visagePosition = positionInd.value
        if playState.value == 1:
            stream.write(pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])
            # pcmPlayProcessLogger.debug('pcmPlayer writing data %s %s %s', playPosition, playPosition + 2 * int(pcmRate * STEP), pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])
            logQueue.put(['debug', 'pcmPlayer writing data %s %s %s' % (playPosition, playPosition + 2 * int(pcmRate * STEP), pcmData[playPosition : playPosition + 2 * int(pcmRate * STEP)])])
            playPosition = playPosition + 2 * int(pcmRate * STEP)
            # updatePlotCount = updatePlotCount + 1
            # if updatePlotCount == 20:    #not precise at all, 10 meant tobe 200ms      STEP * Count
            # updatePlotCount = 0
            try:
                # pcmPlayProcessLogger.debug('pcmPlayer process feedback play position at %s', playPosition)
                logQueue.put(['debug', ('pcmPlayer process feedback play position at %s' % playPosition)])
                q.put(playPosition)
            except Exception as e:
                # pcmPlayProcessLogger.error('pcmPlayer process failed to write playPosition into feedback queue', exc_info=True)
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
        # time.sleep(0.1)

def pcmPlayerProcessLogger(logQueue, logger):
    logger.info('pcmPlayerProcessLogger thread normal start')
    while True:
        try:
            #logQueue.empty() == False:
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
        # self.dataInd = start
        """
        self.p = pyaudio.PyAudio()
        # self.stream = self.p.open(format=FORMAT, channels=CHANNELS, rate=pcmRate, output=True, stream_callback=self.callback)
        self.stream = self.p.open(format=FORMAT, channels=CHANNELS, rate=pcmRate, output=True)
        """
        self.pcmData = pcmData
        self.pcmRate = pcmRate
        self.updatePlotCount = 0
        self.playState = Value('I', self.state)
        self.positionInd = Value('I', start)
        # self.positionFeed = Value('I', start)
        self.p = None
        self.q = Queue()
        self.linePosition = 0
        self.logger.info('pcmPlayer Thread initiated')
        self.pcmPlayProcessLogger = logging.getLogger('pcmPlayProcess')
        self.logQueue = Queue()
        if hasattr(self, 'logThr'):
            self.logger.info('child thread logThr whether still alive: %s', self.logThr.isAlive())
        else:
            self.logger.info('pcmPlayer have no logThr child')
        self.logThr = threading.Thread(target=pcmPlayerProcessLogger, args =(self.logQueue, self.pcmPlayProcessLogger))
        self.logThr.daemon = True
        self.logThr.start()
        self.logger.debug('pcmPlayer initiated, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def run(self):
        self.state = 1
        self.updatePlotCount = 0
        self.playState.value = 1
        # self.positionInd = 0
        self.p = Process(target=processPlayPcm, args=(self.q, self.pcmRate, self.pcmData, self.playState, self.positionInd, self.logQueue))
        self.p.daemon = True
        self.p.start()
        # self.p.join()
        # print(len(self.pcmData) / 2 / self.pcmRate)
        self.logger.info('pcm audio length: %s seconds', len(self.pcmData) / 2 / self.pcmRate)
        while self.p.is_alive():
            try:
                self.linePosition = self.q.get(block = False)
                #while self.q.empty() == False:
                    #self.linePosition = self.q.get(block = False)
                # if len(self.pcmData) / 2 / self.pcmRate < 21:    #10s
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
        """
        while self.dataInd < len(self.pcmData):
            if self.state == 1:
                self.stream.write(self.pcmData[self.dataInd : self.dataInd + 2 * int(self.pcmRate * STEP)])
                self.dataInd = self.dataInd + 2 * int(self.pcmRate * STEP)
                # self.stream.write(self.pcmData[:])
                # print(time.time())

                self.updatePlotCount = self.updatePlotCount + 1
                if self.updatePlotCount == 50:
                    self.updatePlotCount = 0
                    self.emit(QtCore.SIGNAL('refreshMatplotLine(float)'), self.dataInd/len(self.pcmData))

            elif self.state == 2:
                pass
            elif self.state == 0:
                self.stream.stop_stream()
                self.stream.close()
                self.p.terminate()
                break
            # time.sleep(STEP)
        """
    def swapState(self):
        if self.state == 0 or self.state == 2:
            self.state = 1
            self.playState.value = 1
            self.logger.info('pcmPlayer Thread resume playing')
            # self.stream.stop_stream()
        elif self.state == 1:
            self.state = 2
            self.playState.value = 2
            self.logger.info('pcmPlayer Thread paused')
            # self.stream.start_stream()

    def stop(self):
        self.state = 0
        self.playState.value = 0
        self.logger.debug('pcmPlay process is still alive %s', self.p.is_alive())
        time.sleep(0.2)
        self.logger.info('pcmPlayer Thread stopped')
        if self.p.is_alive() == True:
            self.p.terminate()
            self.p.join()
    """
    def callback(self, in_data, frame_count, time_info, status):
        if self.state == 1:
            data = self.pcmData[self.dataInd : self.dataInd + frame_count * 2]
            self.dataInd = self.dataInd + frame_count * 2
            self.updatePlotCount = self.updatePlotCount + 1
            if self.updatePlotCount == 20:
                self.updatePlotCount = 0
                self.emit(QtCore.SIGNAL('refreshMatplotLine(float)'), self.dataInd/len(self.pcmData))
            print(time.time())
            return (data, pyaudio.paContinue)
        elif self.state == 2:
            pass
        elif self.state == 0:
            self.stream.stop_stream()
            self.stream.close()
            self.p.terminate()
    """
            
class decodeAmrThread(QtCore.QThread):
    def __init__(self, amrType, parseResultIndex):
        QtCore.QThread.__init__(self)
        self.amrType = amrType
        self.index = parseResultIndex
        self.bit_amr_wb_list = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0]
        self.bit_amr_list = [95, 103, 118, 134, 148, 159, 204, 244, 39, 0, 0, 0, 0, 0, 0, 0]
        self.logger = logging.getLogger('decodeThr')
        self.logger.info('amr decode thread initiated amrType: %s, parseResultIndex: %s', self.amrType, self.index)
        self.runState = False
        
    # def __del__(self):
        # self.logger.info('decodeAmrThread __del__')
        # self.wait()
        
    def stop(self):
        self.runState = False
        self.logger.info('getting stop event!')
        
    def run(self):
        global pcmList
        global parseResult
        """
        globalSeq = []
        globalLoopCount = 0
        for i in parseResult[self.index][10]:
            globalSeq = i + globalLoopCount * 65536
            if i == 65535:
                globalLoopCount = globalLoopCount + 1
        sortedSeq = np.argsort(globalSeq)
        """
        self.runState = True
        if self.amrType == 'amr':
            pcmList[self.index][0] = self.amrNbDecode(parseResult[self.index][7], parseResult[self.index][11], parseResult[self.index][10])[0]
            pcmList[self.index][1] = 8000
            pcmList[self.index][2] = parseResult[self.index][4]
            # pcmList[self.index][3] = self.amrType
        elif self.amrType == 'amr-wb':
            pcmList[self.index][0] = self.amrWbDecode(parseResult[self.index][7], parseResult[self.index][11], parseResult[self.index][10])[0]
            pcmList[self.index][1] = 16000
            pcmList[self.index][2] = parseResult[self.index][4]
            # pcmList[self.index][3] = self.amrType
        elif self.amrType == 'amr_octet-align':
            pcmList[self.index][0] = self.amrNbDecode(parseResult[self.index][7], parseResult[self.index][11], parseResult[self.index][10], True)[0]
            pcmList[self.index][1] = 8000
            pcmList[self.index][2] = parseResult[self.index][4]
            # pcmList[self.index][3] = self.amrType
        elif self.amrType == 'amr-wb_octet-align':
            pcmList[self.index][0] = self.amrWbDecode(parseResult[self.index][7], parseResult[self.index][11], parseResult[self.index][10], True)[0]
            pcmList[self.index][1] = 16000
            pcmList[self.index][2] = parseResult[self.index][4]
            # pcmList[self.index][3] = self.amrType
        else:
            self.logger.error('unknown payload type! %s', self.amrType)
        self.logger.info('decoding finished, decode thread normal exiting')

    def amrNbDecode(self, amrList, rtpTimeStampList, seqNumber, octetAligned = False):
        global decodeInfo
        dll = ctypes.CDLL(r'amrNbDecoder.dll')
        serial_Array = ctypes.c_ubyte * 32
        serial = serial_Array(0)
        synth_Array = ctypes.c_short * 160
        synth = synth_Array(0)
        destate = dll.Decoder_Interface_init()
        frames = 0
        pcm = b''
        processInt = 0
        shortCounter = 0
        longerCounter = 0
        decodeInfo = ''
        while(frames < len(amrList)):
            if not self.runState:
                decodeInfo = 'decoding cancelled'
                return b'', 0
            if frames*100/len(amrList)>=processInt:
                processInt = processInt + 1
                self.emit(QtCore.SIGNAL('refreshProgressBar()'))
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
            self.logger.debug('frameNumber: %s, frameContent: %s, seqNumber: %s, rtpTimeStamp: %s', frames, amrList[frames], seqNumber[frames] , rtpTimeStampList[frames])
            for t in amrPacketTocList:
                if t < 8:
                    T = bitarray.bitarray('0')
                    T.extend(bin(t)[2:].zfill(4))
                    T.extend('100')
                    if amrPayloadPointer + self.bit_amr_list[t] < len(bitAmrPayload):
                        AmrPayload = T.tobytes() + bitAmrPayload[amrPayloadPointer : amrPayloadPointer + self.bit_amr_list[t]].tobytes()
                        self.logger.debug('AmrPayload: %s', AmrPayload)
                        for i in range(len(AmrPayload)):
                            serial[i] = AmrPayload[i]
                        dll.Decoder_Interface_Decode(destate, serial, synth, 0)
                        pcm = pcm + struct.pack('160h', *synth[:160])
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(self.bit_amr_list[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + self.bit_amr_list[t]
                    else:
                        shortCounter = shortCounter + 1
                        # print('not enough payload! rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                        self.logger.error('not enough payload! rtpTimeStamp: %s, seqNumber: %s', rtpTimeStampList[frames], seqNumber[frames])
                else:
                    if t == 8:
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(self.bit_amr_list[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + self.bit_amr_list[t]
                    # print('amr Nb Toc == ', t, 'padding,  rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                    self.logger.error('amr Nb Toc == %s, padding it, rtpTimeStamp: %s, seqNumber: %s', t, rtpTimeStampList[frames], seqNumber[frames])
                    if len(rtpTimeStampList) == frames + 1:
                        pcm = pcm + b'\x00\x00' * 1280
                    elif rtpTimeStampList[frames+1] - rtpTimeStampList[frames] >= 0:
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] - rtpTimeStampList[frames])
                    else:
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] + 4294967296 - rtpTimeStampList[frames])
                    # break
            # if amrPayloadPointer + math.ceil(self.bit_amr_list[t]/8)*8 - self.bit_amr_list[t] < len(bitAmrPayload) - 1:
            if len(bitAmrPayload) - amrPayloadPointer >= 8:
                # print(amrPayloadPointer)
                # print(amrPayloadPointer + math.ceil(self.bit_amr_list[t]/8)*8 - self.bit_amr_list[t] , len(bitAmrPayload) - 1)
                longerCounter = longerCounter + 1
                # print('payload longer than expected! rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                self.logger.error('payload longer than expected! rtpTimeStamp: %s, seqNumber: %s, amrPayloadPointer: %s, len_bitAmrPayload: %s', rtpTimeStampList[frames], seqNumber[frames], amrPayloadPointer, len(bitAmrPayload))
            frames = frames + 1
        if longerCounter > 0:
            decodeInfo = decodeInfo + str(longerCounter) + ' amr packet longer than expected! '
        if shortCounter > 0:
            decodeInfo = decodeInfo + str(shortCounter) + ' amr packet shorter than expected!'
        return pcm, frames
        
    def amrWbDecode(self, amrList, rtpTimeStampList, seqNumber, octetAligned = False):
        global decodeInfo
        dll = ctypes.CDLL(r'amrWbDecoder.dll')
        serial_Array = ctypes.c_ubyte * 61
        serial = serial_Array(0)
        synth_Array = ctypes.c_short * 320
        synth = synth_Array(0)
        st = dll.D_IF_init()
        frames = 0
        pcm = b''
        processInt = 0
        shortCounter = 0
        longerCounter = 0
        decodeInfo = ''
        while(frames < len(amrList)):
            if not self.runState:
                decodeInfo = 'decoding cancelled'
                return b'', 0
            if frames*100/len(amrList)>=processInt:
                processInt = processInt + 1
                self.emit(QtCore.SIGNAL('refreshProgressBar()'))
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
            self.logger.debug('frameNumber: %s, frameContent: %s, seqNumber: %s, rtpTimeStamp: %s', frames, amrList[frames], seqNumber[frames] , rtpTimeStampList[frames])
            for t in amrPacketTocList:
                if t < 9:
                    T = bitarray.bitarray('0')
                    T.extend(bin(t)[2:].zfill(4))
                    T.extend('100')
                    if amrPayloadPointer + self.bit_amr_wb_list[t] < len(bitAmrPayload):
                        AmrPayload = T.tobytes() + bitAmrPayload[amrPayloadPointer : amrPayloadPointer + self.bit_amr_wb_list[t]].tobytes()
                        self.logger.debug('AmrPayload: %s', AmrPayload)
                        for i in range(len(AmrPayload)):
                            serial[i] = AmrPayload[i]
                        dll.D_IF_decode(st, serial, synth, 0)
                        pcm = pcm + struct.pack('320h', *synth[:320])
                        # amrPayloadPointer = amrPayloadPointer + self.bit_amr_wb_list[t]
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(self.bit_amr_wb_list[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + self.bit_amr_wb_list[t]
                    else:
                        shortCounter = shortCounter + 1
                        # print('not enough payload! rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                        self.logger.error('not enough payload! rtpTimeStamp: %s, seqNumber: %s', rtpTimeStampList[frames], seqNumber[frames])
                else:
                    if t == 9:
                        if octetAligned:
                            amrPayloadPointer = amrPayloadPointer + math.ceil(self.bit_amr_wb_list[t]/8) * 8
                        else:
                            amrPayloadPointer = amrPayloadPointer + self.bit_amr_wb_list[t]
                    # print('amr Wb Toc == ', t, 'padding,  rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                    self.logger.error('amr Wb Toc == %s, padding it, rtpTimeStamp: %s, seqNumber: %s', t, rtpTimeStampList[frames], seqNumber[frames])
                    if len(rtpTimeStampList) == frames + 1:
                        pcm = pcm + b'\x00\x00' * 2560
                    elif rtpTimeStampList[frames+1] - rtpTimeStampList[frames] >= 0:
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] - rtpTimeStampList[frames])
                    else:
                        pcm = pcm + b'\x00\x00' * (rtpTimeStampList[frames+1] + 4294967296 - rtpTimeStampList[frames])
                    # break
            # if amrPayloadPointer + math.ceil(self.bit_amr_wb_list[t]/8)*8 - self.bit_amr_wb_list[t] < len(bitAmrPayload) - 1:
            if len(bitAmrPayload) - amrPayloadPointer >= 8:
                # print(amrPayloadPointer, amrPayloadPointer + math.ceil(self.bit_amr_wb_list[t]/8)*8 - self.bit_amr_wb_list[t], len(bitAmrPayload) - 1)
                longerCounter = longerCounter + 1
                # print('payload longer than expected! rtpTimeStampList:' , rtpTimeStampList[frames] , ' seqNumber:' , seqNumber[frames])
                self.logger.error('payload longer than expected! rtpTimeStamp: %s, seqNumber: %s, amrPayloadPointer: %s, len_bitAmrPayload: %s', rtpTimeStampList[frames], seqNumber[frames], amrPayloadPointer, len(bitAmrPayload))
            frames = frames + 1
        # print(longerCounter, shortCounter)
        if longerCounter > 0:
            decodeInfo = decodeInfo + str(longerCounter) + ' amr packet longer than expected! '
        if shortCounter > 0:
            decodeInfo = decodeInfo + str(shortCounter) + ' amr packet shorter than expected!'
        return pcm, frames

class decodeH264Thread(QtCore.QThread):
    def __init__(self, parseResultIndex):
        QtCore.QThread.__init__(self)
        self.index = parseResultIndex
        self.logger = logging.getLogger('decodeThr')
        self.logger.info('h264 decode thread initiated, parseResultIndex: %s', self.index)
        self.runState = False
        
    # def __del__(self):
        # self.logger.info('decodeH264Thread __del__')
        # self.wait()

    def stop(self):
        self.runState = False
        self.logger.info('getting stop event!')
        
    def run(self):
        global pcmList
        global parseResult
        global decodeInfo
        self.runState = True
        decodeInfo = ''
        processInt = 0
        frames = 0
        payload = b''
        while(frames < len(parseResult[self.index][7])):   # parseResult[self.index][7], parseResult[self.index][11], parseResult[self.index][10]
            if not self.runState:
                decodeInfo = 'decoding cancelled'
                return
            if frames*100/len(parseResult[self.index][7])>=processInt:
                processInt = processInt + 1
                self.emit(QtCore.SIGNAL('refreshProgressBar()'))
            # bitH264Header = bitarray.bitarray(endian='big')
            # bitH264Header.frombytes(parseResult[self.index][7][frames][:2])
            self.logger.debug('current packet FU: %s, rtpTimeStamp: %s, seqNumber: %s', parseResult[self.index][7][frames][0:2], parseResult[self.index][11][frames], parseResult[self.index][10][frames])
            # if parseResult[self.index][7][frames][0:1] == b'g' or parseResult[self.index][7][frames][0:1] == b'h':
            naluHeader = bitarray.bitarray(endian='big')
            naluHeader.frombytes(parseResult[self.index][7][frames][0:2])
            if int(naluHeader[3:8].to01(), 2) == 28:
                if naluHeader[8]:
                    naluHeader = (naluHeader[:3] + naluHeader[11:]).tobytes()
                    self.logger.debug('writing payload header, header: %s', naluHeader)
                    payload = payload + b'\x00\x00\x00\x01' + naluHeader
                self.logger.debug('writing payload: %s', parseResult[self.index][7][frames][2:])
                payload = payload + parseResult[self.index][7][frames][2:]
            elif int(naluHeader[3:8].to01(), 2) <= 8:
                payload = payload + b'\x00\x00\x00\x01' + parseResult[self.index][7][frames]
                self.logger.debug('writing payload sps/pps or other nal, header: %s', parseResult[self.index][7][frames][0:1])
            else:
                self.logger.error('unknown FU identity: %s, rtpTimeStamp: %s, seqNumber: %s', bin(parseResult[self.index][7][frames][0])[2:].zfill(8), parseResult[self.index][11][frames], parseResult[self.index][10][frames])
            """
            if 97 <= parseResult[self.index][7][frames][0] <= 104:
                self.logger.debug('writing payload sps/pps or other nal, header: %s', parseResult[self.index][7][frames][0:1])
                payload = payload + b'\x00\x00\x00\x01' + parseResult[self.index][7][frames]
            elif parseResult[self.index][7][frames][0:1] == b'\x7c':
                if parseResult[self.index][7][frames][1] & 0x80:
                    naluHeader = bitarray.bitarray(endian='big')
                    naluHeader.frombytes(parseResult[self.index][7][frames][0:2])
                    naluHeader = (naluHeader[:3] + naluHeader[11:]).tobytes()
                    self.logger.debug('writing payload header, header: %s', naluHeader)
                    payload = payload + b'\x00\x00\x00\x01' + naluHeader
                self.logger.debug('writing payload: %s', parseResult[self.index][7][frames][2:])
                payload = payload + parseResult[self.index][7][frames][2:]
            else:
                self.logger.error('unknown FU identity: %s, rtpTimeStamp: %s, seqNumber: %s', bin(parseResult[self.index][7][frames][0])[2:].zfill(8), parseResult[self.index][11][frames], parseResult[self.index][10][frames])
            """
            frames = frames + 1
        pcmList[self.index][0] = payload
        pcmList[self.index][1] = ''
        pcmList[self.index][2] = parseResult[self.index][4]
        # pcmList[self.index][3] = ''
        self.logger.info('decodeH264Thread normal exit')

class parserWorkerProcess(multiprocessing.Process):
    def __init__(self, pcapData, packet_num, packetMark, percentInd, receiveJobLock, parserThrState, rtpHashMap, rtpHashMapLock, filename_arr, checkFilenameLock, filename_arr_count, globalSeq, maxTimeDeltaList, feedbackLock, logQueue, refreshProcessQ):
        multiprocessing.Process.__init__(self)
        self.pcapData = pcapData
        self.packet_num = packet_num
        self.packetMark = packetMark
        self.percentInd = percentInd
        self.receiveJobLock = receiveJobLock
        self.parserThrState = parserThrState
        self.rtpHashMap = rtpHashMap
        self.rtpHashMapLock = rtpHashMapLock
        self.filename_arr = filename_arr
        self.checkFilenameLock = checkFilenameLock
        self.filename_arr_count = filename_arr_count
        self.globalSeq = globalSeq
        self.maxTimeDeltaList = maxTimeDeltaList
        self.feedbackLock = feedbackLock
        self.logQueue = logQueue
        self.refreshProcessQ = refreshProcessQ

    def run(self):
        pcap_packet_header = {}
        EthernetII={}
        ip={}
        udp={}
        rtp={}
        while self.parserThrState.value and os.getppid():
            with self.receiveJobLock:
                if self.packetMark.value >= len(self.pcapData):
                    return
                pcap_packet_header['len'] = self.pcapData[self.packetMark.value + 12 : self.packetMark.value + 16]  
                packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
                packetStart = self.packetMark.value
                self.packetMark.value = self.packetMark.value + packet_len + 16
                self.packet_num.value = self.packet_num.value + 1
                if self.packetMark.value * 100 / len(self.pcapData) >= self.percentInd.value:
                    self.percentInd.value = self.percentInd.value + 1
                    self.refreshProcessQ.put(self.percentInd.value)
                    print(self.refreshProcessQ.qsize())
            pcap_packet_header['GMTtime'] = self.pcapData[packetStart : packetStart + 4]
            pcap_packet_header['MicroTime'] = self.pcapData[packetStart + 4 : packetStart + 8]
            pcap_packet_header['caplen'] = self.pcapData[packetStart + 8 : packetStart + 12]
            timeStamp,= struct.unpack('<I',pcap_packet_header['GMTtime'])
            microtime,= struct.unpack('<I',pcap_packet_header['MicroTime'])
            timeArray = time.localtime(timeStamp)         
            PacketTime = str(time.strftime("%Y-%m-%d %H:%M:%S", timeArray))+'.'+str(microtime)    

            if packet_len>54:
                #Ethernet II
                EthernetII['addr_source']=self.pcapData[packetStart+16:packetStart+16+6]
                EthernetII['addr_to']=self.pcapData[packetStart+16+6:packetStart+16+6+6]      
                EthernetII['type']=self.pcapData[packetStart+16+6+6:packetStart+16+6+6+2]  
                # self.logger.debug('EthernetII header: %s', EthernetII)
                #ip
                ip['version']=self.pcapData[packetStart+30:packetStart+31]
                # print(packet_num)
                ipversion,=struct.unpack('B',ip['version'])
                if str(hex(ipversion))[2]=="4":
                    #ipv4
                    if str(hex(ipversion))[3]!="5":
                        # self.logger.error('ip header length: %s, hard code for 20 only! packet number: %s',int(hex(ipversion)[3]) * 4, pcap_packet_header)
                        continue
                    ip['protocol']=self.pcapData[packetStart+30+9:packetStart+30+10]
                    ip['addr_source']=self.pcapData[packetStart+30+12:packetStart+30+16]
                    ip['addr_to']=self.pcapData[packetStart+30+16:packetStart+30+20]
                    ip1,ip2,ip3,ip4=struct.unpack('4B',ip['addr_source'])
                    ip_addr_from=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
                    ip1,ip2,ip3,ip4=struct.unpack('4B',ip['addr_to'])
                    ip_addr_to=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
                    protocol,=struct.unpack('B',ip['protocol'])
                    # self.logger.debug('ipv4 header: %s', ip)
                    if protocol==17:
                        #udp
                        udp['source_port']=self.pcapData[packetStart+50:packetStart+50+2]
                        udp['dest_port']=self.pcapData[packetStart+50+2:packetStart+50+4]
                        udp['length']=struct.unpack('>H', self.pcapData[packetStart+50+4:packetStart+50+6])[0]
                        port1,=struct.unpack('>H',udp['source_port'])
                        port2,=struct.unpack('>H',udp['dest_port'])
                        # self.logger.debug('udp header: %s', udp)
#                       if port1>10000 and 31000<=port2<=31050 or port2>10000 and 31000<=port1<=31050:
                        # if True:
                        if port1>=10000 and port2>=10000 and len(self.pcapData[packetStart+58:packetStart+16+packet_len])>=15:
                            #rtp
                            rtp['first_two_byte']=self.pcapData[packetStart+58:packetStart+58+2]
                            rtp['payload_type']=self.pcapData[packetStart+58+1:packetStart+58+2]
                            payload_type,=struct.unpack('B',rtp['payload_type'])
                            payload_type_num=int(payload_type&0b01111111)
                            rtp['seq_number']=struct.unpack('>H', self.pcapData[packetStart+58+2:packetStart+58+4])[0]
                            rtp['timestamp']=struct.unpack('>L', self.pcapData[packetStart+58+4:packetStart+58+8])[0]
#                        rtp['SSRC']=struct.unpack('>I',self.pcapData[packetStart+58+8:packetStart+58+12])[0]
                            rtp['SSRC']=binascii.hexlify(self.pcapData[packetStart+58+8:packetStart+58+12]).upper()
                            rtp['payload']=self.pcapData[packetStart+58+12:packetStart+16+packet_len]
                            # self.logger.debug('rtp header: %s', rtp)
                            if 96<=payload_type_num<=127:
                                with self.rtpHashMapLock:
                                    if self.rtpHashMap.get(self.pcapData[packetStart+56:packetStart+58+12]) == None:
                                        self.rtpHashMap[self.pcapData[packetStart+56:packetStart+58+12]] = ''
                                        dupFlag=False
                                    else:
                                        dupFlag=True
                                with self.feedbackLock:
                                    if dupFlag == False:
                                        j=0
                                        existFlag = False
                                        while j < self.filename_arr_count.value:
#                                            print j,self.filename_arr_count7
                                            if self.filename_arr[j][0]==ip_addr_from and self.filename_arr[j][1]==str(port1) and self.filename_arr[j][2]==ip_addr_to and self.filename_arr[j][3]==str(port2) and self.filename_arr[j][8]=='PT'+str(payload_type_num) and self.filename_arr[j][9]==rtp['SSRC']:
                                                tempTimeDelta = datetime.datetime.strptime(PacketTime, "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(self.filename_arr[j][5], "%Y-%m-%d %H:%M:%S.%f")
                                                if tempTimeDelta.total_seconds() > self.maxTimeDeltaList[j][0]:
                                                    self.maxTimeDeltaList[j] = [tempTimeDelta.total_seconds(), rtp['seq_number']]
                                                self.filename_arr[j][5]=PacketTime
                                                self.filename_arr[j][6]=self.filename_arr[j][6]+1
                                                self.filename_arr[j][7].append(rtp['payload'])
                                                self.filename_arr[j][10].append(rtp['seq_number'])
                                                self.filename_arr[j][11].append(rtp['timestamp'])
                                                if rtp['seq_number'] + 65536 * self.globalSeq[j][2] > self.globalSeq[j][1]:
                                                    self.globalSeq[j][1] = rtp['seq_number'] + 65536 * self.globalSeq[j][2]
                                                elif rtp['seq_number'] + 65536 * self.globalSeq[j][2] < self.globalSeq[j][0]:
                                                    self.globalSeq[j][0] = rtp['seq_number'] + 65536 * self.globalSeq[j][2]
                                                if rtp['seq_number'] == 65535:
                                                    self.globalSeq[j][2] = self.globalSeq[j][2] + 1
                                                if len(self.filename_arr[j][10]) > 1 and not (self.filename_arr[j][10][-1] - self.filename_arr[j][10][-2] == 1 or (self.filename_arr[j][10][-2] == 65535 and self.filename_arr[j][10][-1] == 0)):
                                                    self.globalSeq[j][3] = self.globalSeq[j][3] + 1
                                                existFlag = True
                                                # self.logger.debug('appending rtp payload to existing stream')
                                            j=j+1
                                        if existFlag == False:
                                            self.filename_arr_count.value = self.filename_arr_count.value + 1
                                            self.filename_arr.append([ip_addr_from, str(port1), ip_addr_to, str(port2), PacketTime, PacketTime, 1, [rtp['payload']], 'PT'+str(payload_type_num), rtp['SSRC'], [rtp['seq_number']], [rtp['timestamp']], 0])
                                            # self.logger.debug('create new member in steam array')
                                            self.globalSeq.append([rtp['seq_number'], rtp['seq_number'], 0, 0])
                                            if rtp['seq_number'] == 65535:
                                                self.globalSeq[j][2] = self.globalSeq[j][2] + 1
                                            self.maxTimeDeltaList.append([0, rtp['seq_number']])
                                    else:
                                        j=0
                                        while j < self.filename_arr_count.value:
                                            if self.filename_arr[j][0]==ip_addr_from and self.filename_arr[j][1]==str(port1) and self.filename_arr[j][2]==ip_addr_to and self.filename_arr[j][3]==str(port2) and self.filename_arr[j][8]=='PT'+str(payload_type_num) and self.filename_arr[j][9]==rtp['SSRC']:
                                                self.filename_arr[j][12] = self.filename_arr[j][12] + 1
                                                # self.logger.debug('recognized as duplicated, stream dup counter++ and discarding')
                                            j=j+1

                else:
                    ip['protocol']=self.pcapData[packetStart+30+6:packetStart+30+7]
                    ip['addr_source']=self.pcapData[packetStart+30+8:packetStart+30+8+16]
                    ip['addr_to']=self.pcapData[packetStart+30+8+16:packetStart+30+8+16+16]
                    ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8=struct.unpack('>8H',ip['addr_source'])
                    ip_addr_from=hex(ip1).replace('0x','')+':'+hex(ip2).replace('0x','')+':'+hex(ip3).replace('0x','')+':'+hex(ip4).replace('0x','')+':'+hex(ip5).replace('0x','')+':'+hex(ip6).replace('0x','')+':'+hex(ip7).replace('0x','')+':'+hex(ip8).replace('0x','')
                    ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8=struct.unpack('>8H',ip['addr_to'])
                    ip_addr_to=hex(ip1).replace('0x','')+':'+hex(ip2).replace('0x','')+':'+hex(ip3).replace('0x','')+':'+hex(ip4).replace('0x','')+':'+hex(ip5).replace('0x','')+':'+hex(ip6).replace('0x','')+':'+hex(ip7).replace('0x','')+':'+hex(ip8).replace('0x','')
                    protocol,=struct.unpack('B',ip['protocol'])
                    # self.logger.debug('ipv6 header: %s', ip)
                    if protocol==17:
                        #udp
                        udp['source_port']=self.pcapData[packetStart+70:packetStart+70+2]
                        udp['dest_port']=self.pcapData[packetStart+70+2:packetStart+70+4]
                        udp['length']=struct.unpack('>H', self.pcapData[packetStart+70+4:packetStart+70+6])[0]
                        port1,=struct.unpack('>H',udp['source_port'])
                        port2,=struct.unpack('>H',udp['dest_port'])
                        # self.logger.debug('udp header: %s', udp)
#                        if port1>=10000 and 31000<=port2<=31050 or port2>=10000 and 31000<=port1<=31050:
                        # if True:
                        if port1>=10000 and port2>=10000 and len(self.pcapData[packetStart+78:packetStart+16+packet_len])>=15:
                            #rtp
                            rtp['first_two_byte']=self.pcapData[packetStart+78:packetStart+78+2]
                            rtp['payload_type']=self.pcapData[packetStart+78+1:packetStart+78+2]
                            payload_type,=struct.unpack('B',rtp['payload_type'])
                            payload_type_num=int(payload_type&0b01111111)
                            rtp['seq_number']=struct.unpack('>H', self.pcapData[packetStart+78+2:packetStart+78+4])[0]
                            rtp['timestamp']=struct.unpack('>L', self.pcapData[packetStart+78+4:packetStart+78+8])[0]
                            rtp['SSRC']=binascii.hexlify(self.pcapData[packetStart+78+8:packetStart+78+12]).upper()
                            rtp['payload']=self.pcapData[packetStart+78+12:packetStart+16+packet_len]
                            # self.logger.debug('rtp header: %s', rtp)
                            if 96<=payload_type_num<=127:
                                with self.rtpHashMapLock:
                                    if self.rtpHashMap.get(self.pcapData[packetStart+76:packetStart+78+12]) == None:
                                        self.rtpHashMap[self.pcapData[packetStart+76:packetStart+78+12]] = ''
                                        dupFlag=False
                                    else:
                                        dupFlag=True
                                with self.feedbackLock:
                                    if dupFlag == False:
                                        j=0
                                        existFlag = False
                                        while j < self.filename_arr_count.value:
#                                            print j,self.filename_arr_count7
                                            if self.filename_arr[j][0]==ip_addr_from and self.filename_arr[j][1]==str(port1) and self.filename_arr[j][2]==ip_addr_to and self.filename_arr[j][3]==str(port2) and self.filename_arr[j][8]=='PT'+str(payload_type_num) and self.filename_arr[j][9]==rtp['SSRC']:
                                                tempTimeDelta = datetime.datetime.strptime(PacketTime, "%Y-%m-%d %H:%M:%S.%f") - datetime.datetime.strptime(self.filename_arr[j][5], "%Y-%m-%d %H:%M:%S.%f")
                                                if tempTimeDelta.total_seconds() > self.maxTimeDeltaList[j][0]:
                                                    self.maxTimeDeltaList[j] = [tempTimeDelta.total_seconds(), rtp['seq_number']]
                                                self.filename_arr[j][5]=PacketTime
                                                self.filename_arr[j][6]=self.filename_arr[j][6]+1
                                                self.filename_arr[j][7].append(rtp['payload'])
                                                self.filename_arr[j][10].append(rtp['seq_number'])
                                                self.filename_arr[j][11].append(rtp['timestamp'])
                                                if rtp['seq_number'] + 65536 * self.globalSeq[j][2] > self.globalSeq[j][1]:
                                                    self.globalSeq[j][1] = rtp['seq_number'] + 65536 * self.globalSeq[j][2]
                                                elif rtp['seq_number'] + 65536 * self.globalSeq[j][2] < self.globalSeq[j][0]:
                                                    self.globalSeq[j][0] = rtp['seq_number'] + 65536 * self.globalSeq[j][2]
                                                if rtp['seq_number'] == 65535:
                                                    self.globalSeq[j][2] = self.globalSeq[j][2] + 1
                                                if len(self.filename_arr[j][10]) > 1 and not (self.filename_arr[j][10][-1] - self.filename_arr[j][10][-2] == 1 or (self.filename_arr[j][10][-2] == 65535 and self.filename_arr[j][10][-1] == 0)):
                                                    self.globalSeq[j][3] = self.globalSeq[j][3] + 1
                                                existFlag = True
                                                # self.logger.debug('appending rtp payload to existing stream')
                                            j=j+1
                                        if existFlag == False:
                                            self.filename_arr_count.value = self.filename_arr_count.value + 1
                                            self.filename_arr.append([ip_addr_from, str(port1), ip_addr_to, str(port2), PacketTime, PacketTime, 1, [rtp['payload']], 'PT'+str(payload_type_num), rtp['SSRC'], [rtp['seq_number']], [rtp['timestamp']], 0])
                                            # self.logger.debug('create new member in steam array')
                                            self.globalSeq.append([rtp['seq_number'], rtp['seq_number'], 0, 0])
                                            if rtp['seq_number'] == 65535:
                                                self.globalSeq[j][2] = self.globalSeq[j][2] + 1
                                            self.maxTimeDeltaList.append([0, rtp['seq_number']])
                                    else:
                                        j=0
                                        while j < self.filename_arr_count.value:
                                            if self.filename_arr[j][0]==ip_addr_from and self.filename_arr[j][1]==str(port1) and self.filename_arr[j][2]==ip_addr_to and self.filename_arr[j][3]==str(port2) and self.filename_arr[j][8]=='PT'+str(payload_type_num) and self.filename_arr[j][9]==rtp['SSRC']:
                                                self.filename_arr[j][12] = self.filename_arr[j][12] + 1
                                                # self.logger.debug('recognized as duplicated, stream dup counter++ and discarding')
                                            j=j+1


class parsePcapThread(QtCore.QThread):
    def __init__(self, pcapFileName):
        QtCore.QThread.__init__(self)
        self.pcapFileName = pcapFileName
        self.logger = logging.getLogger('parserThr')
        self.logger.info('parser thread initiated')
        self.parserThrState = Value('I', 0)
        self.packet_num = Value('I', 0)
        self.packetMark = Value('I', 0)
        self.percentInd = Value('I', 0)
        self.receiveJobLock = Lock()
        self.mgr = multiprocessing.Manager()
        self.rtpHashMap = self.mgr.dict()
        self.rtpHashMapLock = Lock()
        self.filename_arr_count = Value('I', 0)
        self.filename_arr = self.mgr.list()
        self.checkFilenameLock = Lock()
        self.globalSeq = self.mgr.list()
        self.maxTimeDeltaList = self.mgr.list()
        self.feedbackLock = Lock()
        self.logQueue = Queue()
        self.refreshProcessQ = Queue()

    def stop(self):
        self.parserThrState.value = 0
        self.logger.info('parsePcapThread get stop event')

    def run(self):
        global parseResult
        global parseFailInfo
        self.parserThrState.value = 1
        fpcap = open(self.pcapFileName,'rb')
        string_data = fpcap.read()
        fpcap.close()
        if string_data[:4] != b'\xd4\xc3\xb2\xa1':
            parseFailInfo = 'probably not a pcap file!!!'
            self.logger.error('probably not a pcap file %s', self.pcapFileName)
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
        self.logger.debug('pcap file header %s', pcap_header)
        self.packetMark.value = 24
        #                  pcapData,      packet_num,      packetMark,      percentInd,      receiveJobLock,      parserThrState,      rtpHashMap,      rtpHashMapLock,      filename_arr,      checkFilenameLock,      filename_arr_count,      globalSeq,      maxTimeDeltaList,      feedbackLock,      logQueue)
        processArgs = (string_data, self.packet_num, self.packetMark, self.percentInd, self.receiveJobLock, self.parserThrState, self.rtpHashMap, self.rtpHashMapLock, self.filename_arr, self.checkFilenameLock, self.filename_arr_count, self.globalSeq, self.maxTimeDeltaList, self.feedbackLock, self.logQueue, self.refreshProcessQ)
        processList = [parserWorkerProcess(*processArgs) for n in range(cpu_count())]
        for p in processList:
            p.daemon = True
            p.start()

        while self.parserThrState.value:
            try:
                print(self.refreshProcessQ.qsize())
                self.refreshProcessQ.get() # block = False)
                self.emit(QtCore.SIGNAL('refreshProgressBar()'))
                self.logger.debug('parsePcapThread update progressbar +1')
            # except queue.Empty:
            #     time.sleep(0.01)
            #     continue
            except Exception as e:
                self.logger.error('parsePcapThread feedback get error', exc_info=True)

        self.logger.info('pcmPlayer Thread normally exited')
        self.logger.debug('pcmPlayer normal finished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])


        for j in range(len(self.filename_arr)):
            # print(globalSeq[j], filename_arr[j][6])
            self.filename_arr[j].append(self.globalSeq[j][1] - self.globalSeq[j][0] + 1 - self.filename_arr[j][6])
            self.filename_arr[j].append(self.globalSeq[j][3])
            self.filename_arr[j].append(str(round(self.maxTimeDeltaList[j][0],3)) + '/' + str(self.maxTimeDeltaList[j][1]))
            self.logger.debug('filename_arr[%s] max: %s, min: %s, total: %s', j, self.globalSeq[j][1], self.globalSeq[j][0], self.filename_arr[j][6])
        parseResult = self.filename_arr
        self.logger.info('parser thread normal exit')
        self.logger.debug('gc.get_count: %s', gc.get_count())
        self.logger.debug('thread enumerating: %s', [t.getName() for t in threading.enumerate()])

class MatplotlibWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        super(MatplotlibWidget, self).__init__(parent)
        self.figure = Figure(facecolor='white')
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.axis = self.figure.add_subplot(111)
        # self.axis.set_autoscale_on(False)
        # self.axis.set_autoscaley_on(False)
        # self.axis.set_autoscalex_on(False)
        # self.figure.set_size_inches(16, 5)
        # self.figure.tight_layout()
        self.ax2 = self.axis.twiny()
        self.ax2.set_xlim(self.axis.get_xlim())
        self.logger = logging.getLogger('MainThrd')
        """
        self.axis.set_title("Time Domain Plotting")
        self.ax2 = self.axis.twiny()
        self.ax2.set_xlim(self.axis.get_xlim())
        self.axis.set_xlabel("reference time")
        self.ax2.set_xlabel("absolute time")
        self.axis.set_ylabel("amplitude")
        ax.set_axis_bgcolor('white')
        """
        self.layoutVertical = QtGui.QVBoxLayout(self)
        self.layoutVertical.addWidget(self.canvas)
        self.figure.subplots_adjust(left=0.05, bottom=0.1, top=0.85, right=0.95, wspace = 0, hspace = 0)
        # self.figure.tight_layout(False)
        # pl.gcf().subplots_adjust(top=0.15)
        # pl.autoscale(tight = False)
        # pl.margins(x=0, y=0)
        self.position = 0
        self.background = None
        self.line = None
        self.line1 = None
        # self.cid = self.canvas.mpl_connect('button_press_event',self.onclick)
        self.step = 500  # 100ms
    """
    def update(self):
        self.canvas.restore_region(self.background)
        self.line.set_xdata([self.position, self.position])
        self.axis.draw_artist(self.line)
        self.canvas.draw()
        self.logger.debug('updating line position! %s', self.position)

    def onclick(self, event):
        # print('matplotlib canvas user click')
        self.position = event.xdata * self.axis.get_xlim()[1]
        # print(event.xdata)
        self.update()
        self.logger.debug('click event, updating line position! %s', event.xdata)
        
    def timerUpdate(self):
        # print(time.time(), 'timerUpdate!')
        self.canvas.restore_region(self.background)
        self.position = self.position + self.step/1000
        # self.position = self.position + positionFeed
        # print(self.position)
        self.line.set_xdata([self.position, self.position])
        self.axis.draw_artist(self.line)
        self.canvas.draw()
    """
    
class progressLine(QtGui.QWidget):
    def __init__(self, parent=None):
        super(progressLine, self).__init__(parent)
        palette = QtGui.QPalette(self.palette())
        palette.setColor(palette.Background, QtCore.Qt.transparent)
        self.setPalette(palette)
        self.parentWidth = 1680
        self.outerMargin = 9
        self.plotXMargin = 0.05
        self.xPercentage = 0
        self.plotStartPosition = (self.parentWidth - 2 * self.outerMargin) * self.plotXMargin + self.outerMargin
        # normal minds' way of calculation, but ...
        # self.plotWidth = self.parentWidth - self.plotStartPosition * 2
        self.plotWidth = self.parentWidth - self.outerMargin * 2 - self.plotStartPosition * 2 + 2
        # self.plotWidth = (self.parentWidth - 4 * self.outerMargin) * (1 - self.plotXMargin * 2)
        # self.plotWidth = self.width() - self.plotStartPosition * 2 - 18
        # self.xposition = self.plotStartPosition + self.plotWidth * self.xPercentage
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
            # self.plotWidth = (self.parentWidth - 4 * self.outerMargin) * (1 - self.plotXMargin * 2)
            self.plotWidth = self.parentWidth - self.outerMargin * 2 - self.plotStartPosition * 2 + 2
            self.xposition = self.plotWidth * self.xPercentage + self.plotStartPosition
        painter = QtGui.QPainter()
        painter.begin(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.fillRect(event.rect(), QtGui.QBrush(QtGui.QColor(255, 255, 255, 0)))
        painter.drawLine(self.xposition, self.height() * 0, self.xposition, self.height() * 1)
        # print(self.width() * 0, self.height() * 0, self.width() * 1, self.height() * 1)
        # painter.drawLine(1662 * 0.05, self.height() * 0, 1662 * 0.95, self.height() * 1)
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
        """
        if 0 <= self.xPercentage <= 1:
            absoluteTime = self.Duration * self.xPercentage
            referenceTime = self.startTime + datetime.timedelta(seconds = absoluteTime)
            QtGui.QToolTip.showText(self.mapToGlobal(QMouseEvent.pos()), str(round(absoluteTime, 3)) + 's / ' + referenceTime.strftime("%H:%M:%S.%f"), self)
        """
        
    def mouseReleaseEvent(self, event):
        self.xposition = self.mapFromGlobal(event.globalPos()).x()
        self.xPercentage = (self.xposition - self.plotStartPosition)/self.plotWidth
        if 0 <= self.xPercentage <= 1:
            absoluteTime = self.Duration * self.xPercentage
            referenceTime = self.startTime + datetime.timedelta(seconds = absoluteTime)
            QtGui.QToolTip.showText(event.globalPos(), str(round(absoluteTime, 3)) + 's / ' + referenceTime.strftime("%H:%M:%S.%f"), self)
            
    def mouseMoveEvent(self, event):
        self.xposition = self.mapFromGlobal(event.globalPos()).x()
        self.xPercentage = (self.xposition - self.plotStartPosition)/self.plotWidth
        if 0 <= self.xPercentage <= 1:
            absoluteTime = self.Duration * self.xPercentage
            referenceTime = self.startTime + datetime.timedelta(seconds = absoluteTime)
            QtGui.QToolTip.showText(event.globalPos(), str(round(absoluteTime, 3)) + 's / ' + referenceTime.strftime("%H:%M:%S.%f"), self)

class ParsePcapApp(QtGui.QMainWindow, pcapParseUi.Ui_MainWindow):
    def __init__(self):
        super(self.__class__, self).__init__()
        setup_logging()
        self.logger = logging.getLogger('MainThrd')
        self.logger.info('pcapParseGui MainThread initiated')
        self.setupUi(self)
        # self.pcapFileBrowse.clicked.connect(self.browse_pcap_file)
        self.actionPick_a_Pcap_File.triggered.connect(self.browse_pcap_file)
        self.actionPlot_Selected_Stream.triggered.connect(self.pcmPlot)
        self.actionExport_Selected_Line.triggered.connect(self.exportPcm)
        self.actionExit.triggered.connect(self.closeEvent)
        self.actionPlay_2.triggered.connect(self.playPcm)
        self.actionStop.triggered.connect(self.stopPlayPcm)
        self.actionDebug.triggered.connect(self.checkDebug)
        self.actionInfo.triggered.connect(self.checkInfo)
        # self.actionIPS_original.triggered.connect(self.checkDebug)
        # self.actionOptimised.triggered.connect(self.checkDebug)
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
            #print('Loading pt.cfg file error:', e)
            #print(e)
        try:
            if os.path.exists(r'DATA'):
                with open('DATA', 'rb') as f:
                    data = pickle.load(f)
                    if os.path.exists(data['lastPcapFilePath']):
                        self.lastPcapFilePath = data['lastPcapFilePath']
        except Exception as e:
            # print('Loading DATA file error:', e)
            self.logger.error('Loading DATA file error:', exc_info=True)
        self.connect(QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key_Escape), self), QtCore.SIGNAL('activated()'), self.cancelEvent)
        # QtGui.QShortcut(QtGui.QKeySequence('F3'), self).activated.connect(self.parseThread.stop)
        self.progressLine = progressLine(self.matplotlibWidget)
        self.progressLine.hide()
        self.clip = QtGui.QApplication.clipboard()
		
        self.initVarConfig()
		
        # print(self.width(),self.progressLine.width(),self.matplotlibWidget.width())
        # tracker.print_diff()
        self.logger.debug('gc.get_count: %s', gc.get_count())
        self.logger.debug('gc.get_threshold: %s', gc.get_threshold())
		
    def initVarConfig(self):
        self.splitter.setSizes([self.height()//2, self.height()//2])
        self.matplotlibWidget.hide()
        self.setWindowTitle(mainTitle)
        # self.timer = None
        self.progressbar.hide()
        self.progressbar.setMaximum(100)
        self.pcmPlayStartP = 0
        # self.cancelParseButton = QtGui.QPushButton('Cancel')
        # self.actionPick_a_Pcap_File.setEnabled(False)
        self.actionPlot_Selected_Stream.setEnabled(False)
        self.actionExport_Selected_Line.setEnabled(False)
        # self.actionExit.setEnabled(False)
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
        for url in event.mimeData().urls():
            self.browse_pcap_file(str(url.toLocalFile()))
            break
        
    def refreshProgressBar(self):
        self.progressbar.setValue(self.progressbar.value()+1)

    def refreshMatplotLine(self, percentage):
        if percentage < 0 or percentage > 1:
            self.logger.info('change bigger than 1 percentage value to 1, original value from pcmPlayer Thr: %s', percentage)
            percentage = 1
        self.progressLine.xPercentage = percentage
        # print(percentage, self.matplotlibWidget.axis.get_xlim()[1])
        self.progressLine.update()
        """
        self.matplotlibWidget.position = percentage * self.matplotlibWidget.axis.get_xlim()[1]
        self.matplotlibWidget.update()
        """

    def updatePcmPlayRatio(self, percentage):
        global pcmList
        ind = int(percentage * len(pcmList[self.currentPlotted][0]))
        if ind%2 == 1:
            ind = ind - 1
        if self.listenerThr1 != None and self.listenerThr1.isRunning():
            self.listenerThr1.positionInd.value = ind
        self.pcmPlayStartP = ind

    """
    def onclick(self, event):
        print('parsePcap onclick event')
        if event.xdata:
            print(event.xdata)
            self.progressLine._drawLine(100)
            self.logger.info('canvas get user click event: %s', event.xdata)

            self.matplotlibWidget.position = event.xdata * self.matplotlibWidget.axis.get_xlim()[1]
            self.matplotlibWidget.update()
            ind = int(event.xdata * len(pcmList[self.currentPlotted][0]))
            if ind%2 == 1:
                ind = ind - 1
            if self.listenerThr1 != None and self.listenerThr1.isRunning():
                # self.listenerThr1.dataInd = ind
                self.listenerThr1.positionInd.value = ind
            else:
                self.pcmPlayStartP = ind

    """

    def browse_pcap_file(self, pcapFile = ''):
        self.statusBar().clearMessage()
        if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
            self.listenerThr1.stop()
            self.logger.info('pcm player thread force terminated!')
        # self.setCentralWidget(self.tableWidget)
        if pcapFile:
            self.pcapFileName = pcapFile
        else:
            self.pcapFileName, self.openFilter = QtGui.QFileDialog.getOpenFileNameAndFilter(self,'Pick a Pcap File',self.lastPcapFilePath,'Pcap Files(*.pcap);;all files(*.*)',self.openFilter)
            
        if self.pcapFileName:
            self.lastPcapFilePath = os.path.dirname(self.pcapFileName)
            self.progressbar.setValue(0)
            self.progressbar.show()
            self.parseThread = parsePcapThread(self.pcapFileName)
            self.connect(self.parseThread, QtCore.SIGNAL("refreshProgressBar()"), self.refreshProgressBar)
            self.connect(self.parseThread, QtCore.SIGNAL("finished()"), self.parseFinished)
            #self.connect(QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key_Escape), self), QtCore.SIGNAL('activated()'), self.parseThread.stop)
            # QtGui.QShortcut(QtGui.QKeySequence('F3'), self).activated.connect(self.parseThread.stop)
            self.parseThread.start()
            # global pcmList
            # pcmList = []
            # global parseResult
            # parseResult = []
            global parseFailInfo
            parseFailInfo = ''
            self.actionPick_a_Pcap_File.setEnabled(False)
            self.actionPlot_Selected_Stream.setEnabled(False)
            self.actionExport_Selected_Line.setEnabled(False)
            self.actionPlay_2.setEnabled(False)
            self.actionStop.setEnabled(False)
            self.lastWindowTitle = self.windowTitle()
            self.setWindowTitle(mainTitle + str(self.pcapFileName))
            # self.statusbar.addWidget(self.cancelParseButton)
            # self.cancelParseButton.clicked.connect(self.parseFinished)
            try:
                with open('DATA', 'wb') as f:
                    data = {
                        'lastPcapFilePath': self.lastPcapFilePath
                        }
                    pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)
            except Exception as e:
                # print('writing DATA file error:', e)
                self.logger.error('writing DATA file error:', exc_info=True)
            # self.statusBar().showMessage('')

    def parseFinished(self):
        self.progressbar.setValue(100)
        self.parseThread.terminate()
        global parseResult
        global pcmList
        global parseFailInfo
        self.exporting = False
        self.plotting = False
        self.currentExporting = None
        self.currentPlotted = None
        if not parseFailInfo and len(parseResult) > 0:
            self.matplotlibWidget.hide()
            pcmList = []
            self.tableWidget.clear()
            self.tableWidget.setColumnCount(0)
            self.tableWidget.setRowCount(0)
            self.comboboxList = []
            pl.figure(1).clf()
            for i in range(len(parseResult)):
                combobox = QtGui.QComboBox()
                for item in availableAmrOpt:
                    combobox.addItem(item)
                self.comboboxList.append(combobox)
                pcmList.append([b'', 8000, '',''])
                """
                pushbutton1 = QtGui.QPushButton()
                pushbutton1.clicked.connect(self.pcmPlot)
                self.pushbuttonList.append(pushbutton1)
                pushbutton2 = QtGui.QPushButton()
                pushbutton2.clicked.connect(self.exportPcm)
                self.pcmSaveButtonList.append(pushbutton2)
                """
            self.tableWidget.setColumnCount(len(tableHeaders))
            self.tableWidget.setRowCount(len(parseResult))
            self.tableWidget.setHorizontalHeaderLabels(tableHeaders)
            for row in range(len(parseResult)):
                # self.tableWidget.setItem(row,0,QtGui.QTableWidgetItem(str(row+1)))
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
                #self.tableWidget.setItem(row, 14, QtGui.QTableWidgetItem(str(parseResult[row][15])))  # maxJitter
                #self.tableWidget.setItem(row, 15, QtGui.QTableWidgetItem(str(parseResult[row][15])))  # meanJitter
                """
                self.tableWidget.setCellWidget(row, 10, self.pushbuttonList[row])
                self.tableWidget.setCellWidget(row, 11, self.pcmSaveButtonList[row])
                """
            self.tableWidget.resizeColumnsToContents()
            self.showMaximized()
            self.matplotlibWidget.hide()
            # self.splitter.setSizes([self.height(),0])
            self.decodeThread = None

        self.progressbar.hide()
        # self.statusbar.removeWidget(self.progressbar)
        # self.statusbar.removeWidget(self.cancelParseButton)
        self.actionPick_a_Pcap_File.setEnabled(True)
        self.actionPlot_Selected_Stream.setEnabled(True)
        self.actionExport_Selected_Line.setEnabled(True)
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        if parseFailInfo:
            self.statusBar().showMessage(parseFailInfo)
        self.parseThread = None
        # gc.collect()
        # tracker.print_diff()
        self.logger.debug('parseFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def pcmDecode(self, index):
        global decodeInfo
        decodeInfo = ''
        self.statusBar().showMessage('')
        self.progressbar.setValue(0)
        self.progressbar.show()
        if str(self.comboboxList[index].currentText()) == 'h264':
            self.decodeThread = decodeH264Thread(index)
            self.logger.info('main thread starting decodeH264Thread for decoding index %s', index)
        else:
            self.decodeThread = decodeAmrThread(str(self.comboboxList[index].currentText()), index)
            self.logger.info('main thread starting decodeAmrThread for decoding index %s', index)
        self.connect(self.decodeThread, QtCore.SIGNAL("refreshProgressBar()"), self.refreshProgressBar)
        self.connect(self.decodeThread, QtCore.SIGNAL("finished()"), self.decodeFinished)
        self.decodeThread.start()
        self.actionPick_a_Pcap_File.setEnabled(False)
        self.actionPlot_Selected_Stream.setEnabled(False)
        self.actionExport_Selected_Line.setEnabled(False)
        # self.actionExit.setEnabled(False)
        self.actionPlay_2.setEnabled(False)
        self.actionStop.setEnabled(False)

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
                    self.plotWithData(index)
                    self.logger.info('decode finished, main thread start plotting for index %s', index)
            else:
                # print('severe decode error!')
                decodeInfo = decodeInfo + '  NOTHING to plot or export!!!'
                self.logger.error('severe decode error!')
            self.currentPlotting = None
            
        elif self.currentExporting != None:
            index = self.currentExporting
            if pcmList[index][0]:
                self.saveAvFile(index)
                self.logger.info('decode finished, main thread start exporting for index %s', index)
            else:
                decodeInfo = decodeInfo + '  NOTHING to plot or export!!!'
                self.logger.error('severe decode error!')
            self.currentExporting = None
        self.progressbar.hide()
        self.actionPick_a_Pcap_File.setEnabled(True)
        self.actionPlot_Selected_Stream.setEnabled(True)
        self.actionExport_Selected_Line.setEnabled(True)
        # self.actionExit.setEnabled(True)
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        if decodeInfo:
            self.statusBar().showMessage(decodeInfo)
            self.logger.info('decode error summary: %s', decodeInfo)
        # print(self.matplotlibWidget.width(), self.matplotlibWidget.height())
        # print(self.progressLine.width(), self.progressLine.height())
        """
        bbox = self.matplotlibWidget.axis.get_window_extent().transformed(self.matplotlibWidget.figure.dpi_scale_trans.inverted())
        width, height = bbox.width, bbox.height
        print(width, height)
        print(self.progressLine.width(), self.progressLine.height())
        print(self.matplotlibWidget.width(), self.matplotlibWidget.height())
        print(self.splitter.handleWidth())
        # print(width * pl.dpi, height * pl.dpi)
        """
        self.decodeThread = None
        # tracker.print_diff()
        self.logger.debug('decodeFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def plotWithData(self, index):
        self.matplotlibWidget.axis.cla()
        self.matplotlibWidget.ax2.cla()
        global parseResult
        data = np.fromstring(pcmList[index][0], dtype=np.short)
        t = np.arange(0, len(data)/pcmList[index][1], 1.0/pcmList[index][1])
        # self.matplotlibWidget.ax2 = self.matplotlibWidget.axis.twiny()
        # self.matplotlibWidget.ax2.set_xlim(self.matplotlibWidget.axis.get_xlim())
        # self.matplotlibWidget.axis.set_autoscalex_on(False)
        self.matplotlibWidget.axis.set_xlim([0, len(data)/pcmList[index][1]])
        self.matplotlibWidget.axis.set_xlabel("reference time")
        self.matplotlibWidget.ax2.set_xlabel("absolute time")
        self.matplotlibWidget.axis.set_ylabel("amplitude")
        self.matplotlibWidget.axis.set_title("Time Domain Plotting", y = 1.1)
        # self.matplotlibWidget.axis.annotate('local max',xy=(3, 1), horizontalalignment='right', verticalalignment='top')
        line1 = self.matplotlibWidget.axis.plot(t, data, color='black')
        self.matplotlibWidget.axis.grid(True,'major')
        # handles, labels = self.matplotlibWidget.axis.get_legend_handles_labels()
        # for h in handles: h.set_linestyle("None")
        self.matplotlibWidget.figure.legend( line1, ['index:' + str(index+1) + ' ' + '_'.join(parseResult[index][:4])], loc='upper right', fontsize = 10, frameon = True)
        # self.matplotlibWidget.background = self.matplotlibWidget.canvas.copy_from_bbox(self.matplotlibWidget.axis.bbox)
        # x1 = [0, 0]
        # y1 = [self.matplotlibWidget.axis.get_ylim()[0], self.matplotlibWidget.axis.get_ylim()[1]]
        # print(self.matplotlibWidget.axis.get_ylim()[0], self.matplotlibWidget.axis.get_ylim()[1])
        #   self.matplotlibWidget.line, = self.matplotlibWidget.axis.plot(x1, y1, color='red')
        # self.drawProgressLine()
        # self.matplotlibWidget.axis.set_ylim(tuple(y1))
        # print(self.matplotlibWidget.axis.get_xlim(),self.matplotlibWidget.axis.get_ylim())
        new_tick_locations = np.array([0.0, .2, .4, .6, .8, 1.0])
        dt1 = datetime.datetime.strptime(pcmList[index][2], "%Y-%m-%d %H:%M:%S.%f")
        self.matplotlibWidget.ax2.set_xticks(new_tick_locations)
        self.matplotlibWidget.ax2.set_xticklabels([(dt1 + datetime.timedelta(seconds = self.matplotlibWidget.axis.get_xlim()[1] * i)).strftime("%H:%M:%S.%f") for i in new_tick_locations])
        self.matplotlibWidget.canvas.draw()
        # self.cid = self.matplotlibWidget.canvas.mpl_connect('button_press_event',self.onclick)
        # self.splitter.setSizes([self.height()//2, self.height()//2])
        self.matplotlibWidget.show()
        self.progressLine.xPercentage = 0
        self.progressLine.update()
        self.progressLine.Duration = len(data)/pcmList[index][1]
        self.progressLine.startTime = dt1
        self.progressLine.setVisible(True)
        self.pcmPlayStartP = 0
        self.actionPlay_2.setEnabled(True)
        self.actionStop.setEnabled(True)
        self.currentPlotted = index
        self.connect(self.progressLine, QtCore.SIGNAL("updatePcmPlayRatio(float)"), self.updatePcmPlayRatio)

    def resizeEvent(self, event):
        self.progressLine.resize(event.size())
        self.progressLine.parentWidth = self.width()
        self.progressLine.update()
        event.accept()

    def pcmPlot(self):
        self.logger.info('selected rows: %s', [i.row() for i in self.tableWidget.selectionModel().selectedRows()])
        index = self.tableWidget.currentItem().row()
        # print(index)
        if str(self.comboboxList[index].currentText()) == 'h264':
            self.statusBar().showMessage('can not plot h264 video format!')
        else:
            global pcmList
            if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                self.listenerThr1.stop()
            if not (index == None or (index == self.currentPlotted and pcmList[index][3] == str(self.comboboxList[index].currentText()))):
                # pl.figure(1).clf()
                self.statusBar().showMessage('')
                if pcmList[index][0] == b'' or pcmList[index][3] != str(self.comboboxList[index].currentText()):
                    pcmList[index][0] = b''
                    pcmList[index][3] = str(self.comboboxList[index].currentText())
                    self.currentPlotting = index
                    self.pcmDecode(index)
                elif pcmList[index][0] and pcmList[index][3] == str(self.comboboxList[index].currentText()):
                    self.plotWithData(index)

                else:
                    self.logger.error('severe decode error!')

    def exportPcm(self):
        self.logger.info('selected rows: %s', [i.row() for i in self.tableWidget.selectionModel().selectedRows()])
        index = self.tableWidget.currentItem().row()
        # print(index)
        global pcmList
        if index != None:
            if pcmList[index][0] == b'' or pcmList[index][3] != str(self.comboboxList[index].currentText()):
                self.currentExporting = index
                pcmList[index][0] = b''
                pcmList[index][3] = str(self.comboboxList[index].currentText())
                self.pcmDecode(index)
                self.logger.info('decoding index %s before exporting', index)
            elif pcmList[index][0] and pcmList[index][3] == str(self.comboboxList[index].currentText()):
                self.logger.info('export index %s with in-place data', index)
                self.saveAvFile(index)
            else:
                self.logger.critical('severe unknown error!')

    def playPcm(self):
        # print(self.currentPlotted)
        # print(threading.enumerate())
        self.logger.debug('mainThr start playPcm, thread count: %s, thread enumerating: %s', threading.activeCount(), [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())
        if self.currentPlotted >= 0:
            # print(self.listenerThr1)
            if self.listenerThr1 == None or self.listenerThr1.isRunning() == False:
                global pcmList
                if pcmList[self.currentPlotted][0] != b'':
                    """
                    self.logger.info('parseThread whether alive: %s; decodeThread whether alive: %s', self.parseThread.isRunning(), self.decodeThread.isRunning())
                    if self.listenerThr1:
                        self.logger.info('pcmPlayer thread whether still alive: %s', self.listenerThr1.isRunning())
                    else:
                        self.logger.info('pcmPlayer thread not exist')
                    """
                    self.listenerThr1 = pcmPlayer(pcmList[self.currentPlotted][0], self.pcmPlayStartP, pcmList[self.currentPlotted][1])
                    self.connect(self.listenerThr1, QtCore.SIGNAL("refreshMatplotLine(float)"), self.refreshMatplotLine)
                    self.connect(self.listenerThr1, QtCore.SIGNAL("finished()"), self.playPcmFinished)
                    # self.connect(self.progressLine, QtCore.SIGNAL("updatePcmPlayRatio(float)"), self.updatePcmPlayRatio)
                    self.listenerThr1.start()
                    self.statusBar().showMessage('playing started!')
                    """
                    self.timer=self.matplotlibWidget.canvas.new_timer(interval=500)
                    args=[self.listenerThr1.positionFeed.value/len(pcmList[self.currentPlotted][0]) * self.matplotlibWidget.axis.get_xlim()[1]]
                    args = []
                    self.timer.add_callback(self.timerUpdate,*args) # every 100ms it calls update function
                    self.timer.start()
                    """
            else:
                self.listenerThr1.swapState()

    def stopPlayPcm(self):
        if self.listenerThr1.isRunning():
            self.listenerThr1.stop()
            self.listenerThr1 == None
        # print(threading.enumerate())
        # self.logger.info('thread enumerating: %s', [t.getName() for t in threading.enumerate()])

    def playPcmFinished(self):
        # self.matplotlibWidget.position = 0
        # self.matplotlibWidget.update()
        self.pcmPlayStartP = 0
        # self.timer = None
        self.statusBar().showMessage('playing stopped!')
        self.listenerThr1 = None
        self.logger.debug('playFinished, thread enumerating: %s', [t.getName() for t in threading.enumerate()])
        self.logger.debug('gc.get_count: %s', gc.get_count())

    def checkDebug(self):
        self.actionDebug.setChecked(True)
        self.actionInfo.setChecked(False)
        self.logger.handlers[0].setLevel(logging.DEBUG)

    def checkInfo(self):
        self.actionDebug.setChecked(False)
        self.actionInfo.setChecked(True)
        self.logger.handlers[0].setLevel(logging.INFO)

    def closeEvent(self, event):
        quit_msg = "Sure To Exit?"
        reply = QtGui.QMessageBox.question(self, 'Message', quit_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            if self.listenerThr1 != None and self.listenerThr1.isRunning() == True:
                self.listenerThr1.stop()

            if self.ffmpegWrapThr !=None and self.ffmpegWrapThr.isRunning() ==True:
                self.ffmpegWrapThr.saveExit()
                # if self.ffmpegWrapThr.p:
                #     self.ffmpegWrapThr.p.terminate()

            self.logger.info('pcapParseGui MainThread normal exiting')
            QtGui.QApplication.quit()
        else:
            event.ignore()

    def saveAvFile(self, index):
        """
        if pcmList[index][0] == b'':
            self.logger.critical('severe error! pcmList[%s] is b'' while saveAvFile', index)
            return
        """
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
                        t = open(file_path,'wb')
                        t.write(pcmList[index][0])
                        t.close()
                        self.statusBar().showMessage('exported index ' + str(index+1) + ' using raw h264 format to ' + str(file_path))
                        self.logger.info('exported index %s using raw h264 format to %s', index, file_path)
                    except Exception as e:
                        self.logger.error('export to h264 file failed:', exc_info=True)
                        self.statusBar().showMessage('export to h264 file failed')
        else:
            file_path, filter =  QtGui.QFileDialog.getSaveFileNameAndFilter(self,"save pcm file", os.path.join(self.saveFilePath, ('_'.join(parseResult[index][:4])).replace(':',' ')), "pcm files (*.pcm);;wav files (*.wav);;all files(*.*)")
            # print(file_path, filter)
            if file_path:
                self.saveFilePath = os.path.dirname(file_path)
                try:
                    if filter == 'wav files (*.wav)':
                        wf = wave.open(file_path, 'wb')
                        wf.setnchannels(1)
                        wf.setsampwidth(2)
                        wf.setframerate(pcmList[index][1])
                        wf.writeframes(pcmList[index][0])
                        wf.close()
                        self.statusBar().showMessage('exported index ' + str(index+1) + ' using wave format to ' + str(file_path))
                        self.logger.info('exported index %s using wave format to %s', index, file_path)
                    else:
                        t = open(file_path,'wb')
                        t.write(pcmList[index][0])
                        t.close()
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

    """
    def mousePressEvent(self, QMouseEvent):
        print(QMouseEvent.pos())

    def mouseReleaseEvent(self, QMouseEvent):
        cursor =QtGui.QCursor()
        print(cursor.pos())      
    """
    
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

class ffmpegWrapThr(QtCore.QThread):
    def __init__(self, index, file_path):
        QtCore.QThread.__init__(self)
        self.index = index
        self.file_path = file_path
        self.logger = logging.getLogger('MainThrd')
        self.logger.info('ffmpegWrapThr initiated')
        self.p = None
        self.cancelled = False

    """
    # this doesn't work, try terminate subprocess from main thread
    def __del__(self):
        if self.p:
            self.logger.info('ffmpegWrapThr terminating subprocess')
            print('ffmpegWrapThr abnormal exit')
            self.p.terminate()
    """
    def run(self):
        global pcmList
        try:
            input_file = NamedTemporaryFile(mode='wb', delete=False)
            input_file.write(pcmList[self.index][0])
            input_file.flush()
            output = NamedTemporaryFile(mode="rb", delete=False)
            conversion_command = "ffmpeg -y -i " + input_file.name + " -vcodec h264 -f mp4 " + output.name
            self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'converting raw h264 to mp4!')
            self.logger.info('ffmpeg command: %s', conversion_command)
            self.p = subprocess.Popen(conversion_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p_out, p_err = self.p.communicate()
            if self.cancelled == False:
                if self.p.returncode == 0:
                    shutil.copyfile(output.name, self.file_path)
                    self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'exported index ' + str(self.index) + ' using mp4 format to ' + str(self.file_path))
                else:
                    self.emit(QtCore.SIGNAL('subThrUpdateStatusbar(QString)'), 'exported index ' + str(self.index) + ' using mp4 format failed, try raw h264 format')
                    self.logger.error('ffmpeg error, code: %s, error: %s', self.p.returncode, p_err)
            self.logger.info('ffmpegWrapThr normal end')
            self.p = None
            input_file.close()
            output.close()
            os.unlink(input_file.name)
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
        # something may go wrong here when copying and deleting rarely
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

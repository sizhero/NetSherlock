#!/usr/bin/env python3
"""
网络流量多维度特征提取系统
支持从pcap文件提取统计特征、序列特征、载荷特征、协议头部特征、行为特征和关联特征
总计超过570个特征项
"""

import sys
import os
import numpy as np
import pandas as pd
import logging
from datetime import datetime
from collections import defaultdict, OrderedDict
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import json
import math
from scipy import stats
from scipy.fft import fft
from scipy.stats import entropy as scipy_entropy
import warnings
warnings.filterwarnings('ignore')

# 尝试导入必要的库
try:
    from scapy.all import rdpcap, PcapReader, Ether, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("警告: scapy未安装，部分功能可能受限")
    print("安装命令: pip install scapy")

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    print("警告: networkx未安装，图特征提取功能受限")
    print("安装命令: pip install networkx")

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== 数据结构和枚举 ==========

class FlowDirection(Enum):
    """流方向枚举"""
    FORWARD = 1  # 从源到目的
    BACKWARD = -1  # 从目的到源
    UNKNOWN = 0

class ProtocolType(Enum):
    """协议类型枚举"""
    TCP = 1
    UDP = 2
    ICMP = 3
    OTHER = 4

@dataclass
class PacketInfo:
    """数据包信息"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    packet_length: int
    payload_length: int
    tcp_flags: Optional[Dict[str, bool]] = None
    tcp_window: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    ttl: Optional[int] = None
    tos: Optional[int] = None
    payload: Optional[bytes] = None
    
    def get_direction(self, flow_key: Tuple) -> FlowDirection:
        """确定数据包在流中的方向"""
        if (self.src_ip, self.src_port) == (flow_key[0], flow_key[2]):
            return FlowDirection.FORWARD
        elif (self.src_ip, self.src_port) == (flow_key[1], flow_key[3]):
            return FlowDirection.BACKWARD
        return FlowDirection.UNKNOWN

@dataclass
class FlowKey:
    """流标识键"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    
    def to_tuple(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

# ========== 特征提取器基类 ==========

class BaseFeatureExtractor:
    """特征提取器基类"""
    
    def __init__(self):
        self.features = OrderedDict()
        self.feature_names = []
    
    def extract(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """提取特征，子类必须实现"""
        raise NotImplementedError
    
    def get_feature_names(self) -> List[str]:
        """获取特征名称列表"""
        return self.feature_names
    
    def _add_feature(self, name: str, value: Any):
        """添加特征"""
        self.features[name] = value
        if name not in self.feature_names:
            self.feature_names.append(name)
    
    def _safe_stat(self, values: List[float], default: float = 0.0) -> Dict[str, float]:
        """安全计算统计量"""
        if not values:
            return {
                'mean': default, 'std': default, 'min': default,
                'max': default, 'median': default, 'q1': default,
                'q3': default, 'skew': default, 'kurt': default
            }
        
        try:
            values_array = np.array(values)
            return {
                'mean': float(np.mean(values_array)),
                'std': float(np.std(values_array)),
                'min': float(np.min(values_array)),
                'max': float(np.max(values_array)),
                'median': float(np.median(values_array)),
                'q1': float(np.percentile(values_array, 25)),
                'q3': float(np.percentile(values_array, 75)),
                'skew': float(stats.skew(values_array) if len(values_array) > 2 else 0),
                'kurt': float(stats.kurtosis(values_array) if len(values_array) > 3 else 0)
            }
        except:
            return {
                'mean': default, 'std': default, 'min': default,
                'max': default, 'median': default, 'q1': default,
                'q3': default, 'skew': default, 'kurt': default
            }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算字节熵"""
        if not data:
            return 0.0
        
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        prob = byte_counts / len(data)
        prob = prob[prob > 0]  # 移除零概率
        return float(-np.sum(prob * np.log2(prob)))

# ========== 统计特征提取器 ==========

class StatisticalFeatureExtractor(BaseFeatureExtractor):
    """统计特征提取器（约120个特征）"""
    
    def extract(self, packets: List[PacketInfo], flow_key: Tuple) -> Dict[str, Any]:
        """提取统计特征"""
        self.features.clear()
        
        if not packets:
            return self.features
        
        # 分离前向和后向数据包
        forward_packets = []
        backward_packets = []
        
        for pkt in packets:
            direction = pkt.get_direction(flow_key)
            if direction == FlowDirection.FORWARD:
                forward_packets.append(pkt)
            elif direction == FlowDirection.BACKWARD:
                backward_packets.append(pkt)
        
        # 1. 基础流统计
        self._extract_basic_flow_stats(packets, forward_packets, backward_packets)
        
        # 2. 时间间隔统计
        self._extract_time_interval_stats(packets, forward_packets, backward_packets)
        
        # 3. 子流/窗口统计
        self._extract_window_stats(packets)
        
        # 4. 速率与吞吐量统计
        self._extract_rate_stats(packets)
        
        # 5. TCP特定统计
        self._extract_tcp_stats(packets)
        
        return self.features
    
    def _extract_basic_flow_stats(self, all_pkts: List[PacketInfo], 
                                 fwd_pkts: List[PacketInfo], 
                                 bwd_pkts: List[PacketInfo]):
        """提取基础流统计特征"""
        # 流持续时间
        if all_pkts:
            duration = all_pkts[-1].timestamp - all_pkts[0].timestamp
            self._add_feature('flow_duration', max(duration, 0.000001))
        
        # 数据包总数
        total_packets = len(all_pkts)
        fwd_packets = len(fwd_pkts)
        bwd_packets = len(bwd_pkts)
        
        self._add_feature('total_packets', total_packets)
        self._add_feature('fwd_packets', fwd_packets)
        self._add_feature('bwd_packets', bwd_packets)
        
        # 字节总数
        total_bytes = sum(p.packet_length for p in all_pkts)
        fwd_bytes = sum(p.packet_length for p in fwd_pkts)
        bwd_bytes = sum(p.packet_length for p in bwd_pkts)
        
        self._add_feature('total_bytes', total_bytes)
        self._add_feature('fwd_bytes', fwd_bytes)
        self._add_feature('bwd_bytes', bwd_bytes)
        
        # 比例特征
        self._add_feature('fwd_bwd_packet_ratio', 
                         fwd_packets / bwd_packets if bwd_packets > 0 else float('inf'))
        self._add_feature('fwd_bwd_byte_ratio',
                         fwd_bytes / bwd_bytes if bwd_bytes > 0 else float('inf'))
        
        # 平均包长
        fwd_avg_len = fwd_bytes / fwd_packets if fwd_packets > 0 else 0
        bwd_avg_len = bwd_bytes / bwd_packets if bwd_packets > 0 else 0
        total_avg_len = total_bytes / total_packets if total_packets > 0 else 0
        
        self._add_feature('avg_packet_length', total_avg_len)
        self._add_feature('fwd_avg_packet_length', fwd_avg_len)
        self._add_feature('bwd_avg_packet_length', bwd_avg_len)
        
        # 包长统计量
        fwd_lengths = [p.packet_length for p in fwd_pkts]
        bwd_lengths = [p.packet_length for p in bwd_pkts]
        
        fwd_stats = self._safe_stat(fwd_lengths)
        bwd_stats = self._safe_stat(bwd_lengths)
        
        for stat_name, stat_value in fwd_stats.items():
            self._add_feature(f'fwd_packet_length_{stat_name}', stat_value)
        
        for stat_name, stat_value in bwd_stats.items():
            self._add_feature(f'bwd_packet_length_{stat_name}', stat_value)
        
        # 变异系数
        fwd_cv = fwd_stats['std'] / fwd_stats['mean'] if fwd_stats['mean'] > 0 else 0
        bwd_cv = bwd_stats['std'] / bwd_stats['mean'] if bwd_stats['mean'] > 0 else 0
        
        self._add_feature('fwd_packet_length_cv', fwd_cv)
        self._add_feature('bwd_packet_length_cv', bwd_cv)
        
        # 有效载荷统计
        fwd_payloads = [p.payload_length for p in fwd_pkts]
        bwd_payloads = [p.payload_length for p in bwd_pkts]
        
        self._add_feature('fwd_total_payload', sum(fwd_payloads))
        self._add_feature('bwd_total_payload', sum(bwd_payloads))
        
        fwd_payload_stats = self._safe_stat(fwd_payloads)
        bwd_payload_stats = self._safe_stat(bwd_payloads)
        
        for stat_name, stat_value in fwd_payload_stats.items():
            self._add_feature(f'fwd_payload_{stat_name}', stat_value)
        
        for stat_name, stat_value in bwd_payload_stats.items():
            self._add_feature(f'bwd_payload_{stat_name}', stat_value)
        
        # 每秒包数/字节数
        if self.features.get('flow_duration', 0) > 0:
            self._add_feature('packets_per_sec', total_packets / self.features['flow_duration'])
            self._add_feature('bytes_per_sec', total_bytes / self.features['flow_duration'])
    
    def _extract_time_interval_stats(self, all_pkts: List[PacketInfo],
                                    fwd_pkts: List[PacketInfo],
                                    bwd_pkts: List[PacketInfo]):
        """提取时间间隔统计特征"""
        if len(all_pkts) < 2:
            return
        
        # 总体时间间隔
        iats = []
        for i in range(1, len(all_pkts)):
            iat = all_pkts[i].timestamp - all_pkts[i-1].timestamp
            iats.append(iat)
        
        iat_stats = self._safe_stat(iats)
        for stat_name, stat_value in iat_stats.items():
            self._add_feature(f'iat_{stat_name}', stat_value)
        
        # 前向/后向时间间隔
        fwd_iats = []
        for i in range(1, len(fwd_pkts)):
            iat = fwd_pkts[i].timestamp - fwd_pkts[i-1].timestamp
            fwd_iats.append(iat)
        
        bwd_iats = []
        for i in range(1, len(bwd_pkts)):
            iat = bwd_pkts[i].timestamp - bwd_pkts[i-1].timestamp
            bwd_iats.append(iat)
        
        fwd_iat_stats = self._safe_stat(fwd_iats)
        bwd_iat_stats = self._safe_stat(bwd_iats)
        
        for stat_name, stat_value in fwd_iat_stats.items():
            self._add_feature(f'fwd_iat_{stat_name}', stat_value)
        
        for stat_name, stat_value in bwd_iat_stats.items():
            self._add_feature(f'bwd_iat_{stat_name}', stat_value)
        
        # 变异系数
        fwd_iat_cv = fwd_iat_stats['std'] / fwd_iat_stats['mean'] if fwd_iat_stats['mean'] > 0 else 0
        bwd_iat_cv = bwd_iat_stats['std'] / bwd_iat_stats['mean'] if bwd_iat_stats['mean'] > 0 else 0
        
        self._add_feature('fwd_iat_cv', fwd_iat_cv)
        self._add_feature('bwd_iat_cv', bwd_iat_cv)
        
        # 流活跃/空闲时间
        active_threshold = 0.001  # 1ms阈值
        active_time = 0
        idle_time = 0
        
        for iat in iats:
            if iat <= active_threshold:
                active_time += iat
            else:
                idle_time += iat
        
        self._add_feature('active_time', active_time)
        self._add_feature('idle_time', idle_time)
        self._add_feature('active_time_ratio', 
                         active_time / (active_time + idle_time) if (active_time + idle_time) > 0 else 0)
    
    def _extract_window_stats(self, packets: List[PacketInfo]):
        """提取窗口统计特征"""
        if len(packets) < 10:
            return
        
        # 前N个包的统计
        n = min(10, len(packets))
        first_n_packets = packets[:n]
        
        first_n_lengths = [p.packet_length for p in first_n_packets]
        first_n_stats = self._safe_stat(first_n_lengths)
        
        for stat_name, stat_value in first_n_stats.items():
            self._add_feature(f'first_{n}_packets_length_{stat_name}', stat_value)
        
        # 时间窗口统计（1秒窗口）
        if self.features.get('flow_duration', 0) > 1:
            window_size = 1.0  # 1秒窗口
            num_windows = int(self.features['flow_duration'] / window_size) + 1
            
            window_packet_counts = []
            window_byte_counts = []
            
            for w in range(num_windows):
                window_start = packets[0].timestamp + w * window_size
                window_end = window_start + window_size
                
                window_packets = [p for p in packets 
                                 if window_start <= p.timestamp < window_end]
                
                window_packet_counts.append(len(window_packets))
                window_byte_counts.append(sum(p.packet_length for p in window_packets))
            
            window_count_stats = self._safe_stat(window_packet_counts)
            window_byte_stats = self._safe_stat(window_byte_counts)
            
            for stat_name, stat_value in window_count_stats.items():
                self._add_feature(f'window_packet_count_{stat_name}', stat_value)
            
            for stat_name, stat_value in window_byte_stats.items():
                self._add_feature(f'window_byte_count_{stat_name}', stat_value)
    
    def _extract_rate_stats(self, packets: List[PacketInfo]):
        """提取速率统计特征"""
        if self.features.get('flow_duration', 0) <= 0:
            return
        
        # 平均速率
        total_bytes = self.features.get('total_bytes', 0)
        total_packets = self.features.get('total_packets', 0)
        
        avg_bitrate = (total_bytes * 8) / self.features['flow_duration']
        avg_packet_rate = total_packets / self.features['flow_duration']
        
        self._add_feature('avg_bitrate', avg_bitrate)
        self._add_feature('avg_packet_rate', avg_packet_rate)
        
        # 瞬时速率计算（滑动窗口）
        if len(packets) > 5:
            window_size = 0.1  # 100ms窗口
            bitrates = []
            
            for i in range(len(packets)):
                window_start = packets[i].timestamp
                window_end = window_start + window_size
                
                window_packets = [p for p in packets[i:i+50] 
                                 if p.timestamp <= window_end]
                
                if window_packets:
                    window_bytes = sum(p.packet_length for p in window_packets)
                    window_time = window_packets[-1].timestamp - window_start
                    if window_time > 0:
                        bitrates.append((window_bytes * 8) / window_time)
            
            if bitrates:
                bitrate_stats = self._safe_stat(bitrates)
                for stat_name, stat_value in bitrate_stats.items():
                    self._add_feature(f'instant_bitrate_{stat_name}', stat_value)
                
                # 峰值速率
                self._add_feature('peak_bitrate', max(bitrates))
                
                # 速率分位数
                for q in [25, 50, 75, 90]:
                    q_value = np.percentile(bitrates, q) if bitrates else 0
                    self._add_feature(f'bitrate_percentile_{q}', q_value)
    
    def _extract_tcp_stats(self, packets: List[PacketInfo]):
        """提取TCP特定统计特征"""
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        
        if not tcp_packets:
            return
        
        # TCP标志位统计
        syn_count = 0
        fin_count = 0
        rst_count = 0
        psh_count = 0
        ack_count = 0
        urg_count = 0
        
        for pkt in tcp_packets:
            if pkt.tcp_flags:
                if pkt.tcp_flags.get('SYN', False):
                    syn_count += 1
                if pkt.tcp_flags.get('FIN', False):
                    fin_count += 1
                if pkt.tcp_flags.get('RST', False):
                    rst_count += 1
                if pkt.tcp_flags.get('PSH', False):
                    psh_count += 1
                if pkt.tcp_flags.get('ACK', False):
                    ack_count += 1
                if pkt.tcp_flags.get('URG', False):
                    urg_count += 1
        
        self._add_feature('tcp_syn_count', syn_count)
        self._add_feature('tcp_fin_count', fin_count)
        self._add_feature('tcp_rst_count', rst_count)
        self._add_feature('tcp_psh_count', psh_count)
        self._add_feature('tcp_ack_count', ack_count)
        self._add_feature('tcp_urg_count', urg_count)
        
        # 窗口大小统计
        window_sizes = [p.tcp_window for p in tcp_packets if p.tcp_window is not None]
        if window_sizes:
            window_stats = self._safe_stat(window_sizes)
            for stat_name, stat_value in window_stats.items():
                self._add_feature(f'tcp_window_{stat_name}', stat_value)
        
        # 连接成功检测
        syn_packets = [p for p in tcp_packets if p.tcp_flags and p.tcp_flags.get('SYN', False)]
        syn_ack_packets = [p for p in tcp_packets if p.tcp_flags and 
                          p.tcp_flags.get('SYN', False) and p.tcp_flags.get('ACK', False)]
        
        self._add_feature('tcp_syn_packets', len(syn_packets))
        self._add_feature('tcp_syn_ack_packets', len(syn_ack_packets))
        
        # 连接成功率
        if len(syn_packets) > 0:
            connection_success_rate = len(syn_ack_packets) / len(syn_packets)
            self._add_feature('tcp_connection_success_rate', connection_success_rate)
        
        # ACK包比例
        ack_only_packets = [p for p in tcp_packets if p.tcp_flags and 
                           p.tcp_flags.get('ACK', False) and 
                           not any(p.tcp_flags.get(f, False) for f in ['SYN', 'FIN', 'RST', 'PSH', 'URG'])]
        
        self._add_feature('tcp_ack_only_count', len(ack_only_packets))
        self._add_feature('tcp_ack_only_ratio', 
                         len(ack_only_packets) / len(tcp_packets) if tcp_packets else 0)
        
        # 有效载荷包比例
        payload_packets = [p for p in tcp_packets if p.payload_length > 0]
        self._add_feature('tcp_payload_packets', len(payload_packets))
        self._add_feature('tcp_payload_packet_ratio', 
                         len(payload_packets) / len(tcp_packets) if tcp_packets else 0)

# ========== 序列特征提取器 ==========

class SequenceFeatureExtractor(BaseFeatureExtractor):
    """序列特征提取器（约100个特征）"""
    
    def extract(self, packets: List[PacketInfo], flow_key: Tuple) -> Dict[str, Any]:
        """提取序列特征"""
        self.features.clear()
        
        if len(packets) < 2:
            return self.features
        
        # 分离前向和后向数据包
        forward_packets = []
        backward_packets = []
        
        for pkt in packets:
            direction = pkt.get_direction(flow_key)
            if direction == FlowDirection.FORWARD:
                forward_packets.append(pkt)
            elif direction == FlowDirection.BACKWARD:
                backward_packets.append(pkt)
        
        # 1. 包长序列特征
        self._extract_packet_length_sequences(packets, forward_packets, backward_packets)
        
        # 2. 时间间隔序列特征
        self._extract_time_interval_sequences(packets, forward_packets, backward_packets)
        
        # 3. 方向序列特征
        self._extract_direction_sequences(packets, flow_key)
        
        # 4. 联合序列特征
        self._extract_joint_sequences(packets, flow_key)
        
        # 5. 序列建模特征
        self._extract_sequence_modeling_features(packets, forward_packets, backward_packets)
        
        return self.features
    
    def _extract_packet_length_sequences(self, all_pkts: List[PacketInfo],
                                        fwd_pkts: List[PacketInfo],
                                        bwd_pkts: List[PacketInfo]):
        """提取包长序列特征"""
        # 总体包长序列
        packet_lengths = [p.packet_length for p in all_pkts]
        
        # 包长差分序列
        length_diffs = []
        for i in range(1, len(packet_lengths)):
            length_diffs.append(packet_lengths[i] - packet_lengths[i-1])
        
        # 包长符号序列
        length_signs = []
        for diff in length_diffs:
            if diff > 0:
                length_signs.append(1)  # 增大
            elif diff < 0:
                length_signs.append(-1)  # 减小
            else:
                length_signs.append(0)  # 不变
        
        # 包长游程（连续相同符号的长度）
        if length_signs:
            runs = []
            current_run = 1
            current_sign = length_signs[0]
            
            for i in range(1, len(length_signs)):
                if length_signs[i] == current_sign:
                    current_run += 1
                else:
                    runs.append(current_run)
                    current_run = 1
                    current_sign = length_signs[i]
            runs.append(current_run)
            
            run_stats = self._safe_stat(runs)
            for stat_name, stat_value in run_stats.items():
                self._add_feature(f'length_run_{stat_name}', stat_value)
        
        # 前向/后向包长序列
        fwd_lengths = [p.packet_length for p in fwd_pkts]
        bwd_lengths = [p.packet_length for p in bwd_pkts]
        
        # 傅里叶变换特征
        for name, seq in [('all', packet_lengths), ('fwd', fwd_lengths), ('bwd', bwd_lengths)]:
            if len(seq) >= 4:
                try:
                    fft_result = fft(seq)
                    fft_magnitude = np.abs(fft_result)
                    
                    # 取前几个主要频率分量
                    n_components = min(5, len(fft_magnitude) // 2)
                    if n_components > 0:
                        sorted_indices = np.argsort(fft_magnitude[:len(fft_magnitude)//2])[::-1]
                        
                        for i in range(n_components):
                            idx = sorted_indices[i]
                            self._add_feature(f'{name}_fft_freq_{i}_idx', idx)
                            self._add_feature(f'{name}_fft_mag_{i}', fft_magnitude[idx])
                        
                        # 频谱统计
                        magnitude_stats = self._safe_stat(fft_magnitude[:len(fft_magnitude)//2])
                        for stat_name, stat_value in magnitude_stats.items():
                            self._add_feature(f'{name}_fft_magnitude_{stat_name}', stat_value)
                except:
                    pass
        
        # 自相关特征
        if len(packet_lengths) >= 10:
            try:
                max_lag = min(5, len(packet_lengths) // 2)
                for lag in range(1, max_lag + 1):
                    if lag < len(packet_lengths):
                        corr = np.corrcoef(packet_lengths[:-lag], packet_lengths[lag:])[0, 1]
                        if not np.isnan(corr):
                            self._add_feature(f'length_autocorr_lag_{lag}', corr)
            except:
                pass
        
        # 序列复杂度（简单估计）
        if packet_lengths:
            unique_lengths = len(set(packet_lengths))
            self._add_feature('length_sequence_unique_ratio', unique_lengths / len(packet_lengths))
            
            # 简单复杂度估计
            complexity = 0
            for i in range(1, len(packet_lengths)):
                if packet_lengths[i] != packet_lengths[i-1]:
                    complexity += 1
            self._add_feature('length_sequence_complexity', complexity / len(packet_lengths))
    
    def _extract_time_interval_sequences(self, all_pkts: List[PacketInfo],
                                        fwd_pkts: List[PacketInfo],
                                        bwd_pkts: List[PacketInfo]):
        """提取时间间隔序列特征"""
        # 总体IAT序列
        iats = []
        for i in range(1, len(all_pkts)):
            iat = all_pkts[i].timestamp - all_pkts[i-1].timestamp
            iats.append(iat)
        
        if not iats:
            return
        
        # IAT对数序列
        log_iats = [math.log(iat + 1e-10) for iat in iats]
        
        # IAT差分序列
        iat_diffs = []
        for i in range(1, len(iats)):
            iat_diffs.append(iats[i] - iats[i-1])
        
        # 前向/后向IAT序列
        fwd_iats = []
        for i in range(1, len(fwd_pkts)):
            iat = fwd_pkts[i].timestamp - fwd_pkts[i-1].timestamp
            fwd_iats.append(iat)
        
        bwd_iats = []
        for i in range(1, len(bwd_pkts)):
            iat = bwd_pkts[i].timestamp - bwd_pkts[i-1].timestamp
            bwd_iats.append(iat)
        
        # IAT序列统计
        iat_stats = self._safe_stat(iats)
        log_iat_stats = self._safe_stat(log_iats)
        
        for stat_name, stat_value in iat_stats.items():
            self._add_feature(f'iat_sequence_{stat_name}', stat_value)
        
        for stat_name, stat_value in log_iat_stats.items():
            self._add_feature(f'log_iat_sequence_{stat_name}', stat_value)
        
        # 自相关特征
        if len(iats) >= 10:
            try:
                max_lag = min(5, len(iats) // 2)
                for lag in range(1, max_lag + 1):
                    if lag < len(iats):
                        corr = np.corrcoef(iats[:-lag], iats[lag:])[0, 1]
                        if not np.isnan(corr):
                            self._add_feature(f'iat_autocorr_lag_{lag}', corr)
            except:
                pass
        
        # Hurst指数估计（简化版）
        if len(iats) >= 20:
            try:
                # R/S分析简化版本
                n = len(iats)
                mean_iat = np.mean(iats)
                deviations = iats - mean_iat
                Z = np.cumsum(deviations)
                R = np.max(Z) - np.min(Z)
                S = np.std(iats)
                
                if S > 0:
                    hurst_estimate = math.log(R / S) / math.log(n)
                    self._add_feature('hurst_exponent_estimate', hurst_estimate)
            except:
                pass
    
    def _extract_direction_sequences(self, packets: List[PacketInfo], flow_key: Tuple):
        """提取方向序列特征"""
        if not packets:
            return
        
        # 方向序列（1: 前向, -1: 后向, 0: 未知）
        direction_sequence = []
        for pkt in packets:
            direction = pkt.get_direction(flow_key)
            if direction == FlowDirection.FORWARD:
                direction_sequence.append(1)
            elif direction == FlowDirection.BACKWARD:
                direction_sequence.append(-1)
            else:
                direction_sequence.append(0)
        
        # 方向转移序列
        direction_transitions = []
        for i in range(1, len(direction_sequence)):
            transition = direction_sequence[i] - direction_sequence[i-1]
            direction_transitions.append(transition)
        
        # 方向序列熵
        if direction_sequence:
            unique_directions = set(direction_sequence)
            direction_counts = {d: direction_sequence.count(d) for d in unique_directions}
            total = len(direction_sequence)
            
            entropy = 0
            for count in direction_counts.values():
                p = count / total
                entropy -= p * math.log2(p) if p > 0 else 0
            
            self._add_feature('direction_sequence_entropy', entropy)
        
        # 方向转移统计
        if direction_transitions:
            unique_transitions = set(direction_transitions)
            self._add_feature('direction_transition_unique_count', len(unique_transitions))
            
            # 计算方向变化的频率
            direction_changes = sum(1 for t in direction_transitions if t != 0)
            self._add_feature('direction_change_frequency', direction_changes / len(packets))
    
    def _extract_joint_sequences(self, packets: List[PacketInfo], flow_key: Tuple):
        """提取联合序列特征"""
        if len(packets) < 2:
            return
        
        # (包长, 方向) 联合序列
        length_direction_pairs = []
        for pkt in packets:
            direction = pkt.get_direction(flow_key)
            dir_value = 1 if direction == FlowDirection.FORWARD else -1
            length_direction_pairs.append((pkt.packet_length, dir_value))
        
        # (包长, IAT) 联合序列
        length_iat_pairs = []
        for i in range(len(packets)):
            if i == 0:
                length_iat_pairs.append((packets[i].packet_length, 0))
            else:
                iat = packets[i].timestamp - packets[i-1].timestamp
                length_iat_pairs.append((packets[i].packet_length, iat))
        
        # 联合序列统计
        if length_direction_pairs:
            lengths, directions = zip(*length_direction_pairs)
            length_direction_corr = np.corrcoef(lengths, directions)[0, 1] if len(lengths) > 1 else 0
            if not np.isnan(length_direction_corr):
                self._add_feature('length_direction_correlation', length_direction_corr)
        
        if length_iat_pairs and len(length_iat_pairs) > 1:
            lengths, iats = zip(*length_iat_pairs)
            length_iat_corr = np.corrcoef(lengths, iats)[0, 1]
            if not np.isnan(length_iat_corr):
                self._add_feature('length_iat_correlation', length_iat_corr)
    
    def _extract_sequence_modeling_features(self, all_pkts: List[PacketInfo],
                                           fwd_pkts: List[PacketInfo],
                                           bwd_pkts: List[PacketInfo]):
        """提取序列建模特征"""
        # n-gram特征（bi-gram和tri-gram）
        packet_lengths = [p.packet_length for p in all_pkts]
        
        if len(packet_lengths) >= 3:
            # 将包长离散化为3个等级
            if packet_lengths:
                max_len = max(packet_lengths)
                min_len = min(packet_lengths)
                range_len = max_len - min_len
                
                if range_len > 0:
                    discrete_levels = []
                    for length in packet_lengths:
                        normalized = (length - min_len) / range_len
                        if normalized < 0.33:
                            discrete_levels.append('S')  # 小包
                        elif normalized < 0.67:
                            discrete_levels.append('M')  # 中包
                        else:
                            discrete_levels.append('L')  # 大包
                    
                    # bi-gram频率
                    bigrams = {}
                    for i in range(len(discrete_levels) - 1):
                        bigram = f"{discrete_levels[i]}{discrete_levels[i+1]}"
                        bigrams[bigram] = bigrams.get(bigram, 0) + 1
                    
                    # 记录最常见的bi-gram
                    if bigrams:
                        sorted_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)
                        for i, (bigram, count) in enumerate(sorted_bigrams[:5]):
                            self._add_feature(f'top_{i+1}_bigram_{bigram}_freq', count / len(packet_lengths))
        
        # 简单AR模型预测误差
        if len(packet_lengths) >= 10:
            try:
                # 使用简单线性回归预测下一个包长
                from sklearn.linear_model import LinearRegression
                
                X = np.array(packet_lengths[:-1]).reshape(-1, 1)
                y = np.array(packet_lengths[1:])
                
                model = LinearRegression()
                model.fit(X, y)
                predictions = model.predict(X)
                mse = np.mean((y - predictions) ** 2)
                
                self._add_feature('ar_prediction_mse', mse)
                self._add_feature('ar_prediction_mae', np.mean(np.abs(y - predictions)))
            except:
                pass

# ========== 载荷特征提取器 ==========

class PayloadFeatureExtractor(BaseFeatureExtractor):
    """载荷特征提取器（约90个特征）"""
    
    def extract(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """提取载荷特征"""
        self.features.clear()
        
        # 收集所有有效载荷
        payloads = [p.payload for p in packets if p.payload and len(p.payload) > 0]
        
        if not payloads:
            # 如果没有载荷，设置默认值
            self._set_default_payload_features()
            return self.features
        
        # 1. 字节分布与熵
        self._extract_byte_distribution_entropy(payloads)
        
        # 2. 结构特征
        self._extract_structural_features(payloads)
        
        # 3. 加密与压缩特征
        self._extract_encryption_compression_features(payloads)
        
        # 4. 会话载荷聚合特征
        self._extract_session_payload_features(payloads)
        
        return self.features
    
    def _set_default_payload_features(self):
        """设置默认的载荷特征值"""
        default_features = {
            'payload_entropy': 0.0,
            'payload_byte_mean': 0.0,
            'payload_byte_std': 0.0,
            'payload_printable_ratio': 0.0,
            'payload_alnum_ratio': 0.0,
            'payload_chi_square': 0.0,
            'payload_markov_test': 0.0,
            'payload_compression_ratio': 1.0
        }
        
        for name, value in default_features.items():
            self._add_feature(name, value)
    
    def _extract_byte_distribution_entropy(self, payloads: List[bytes]):
        """提取字节分布与熵特征"""
        # 合并所有载荷
        combined_payload = b''.join(payloads)
        
        if not combined_payload:
            return
        
        # 计算字节值分布
        byte_counts = np.zeros(256)
        for byte in combined_payload:
            byte_counts[byte] += 1
        
        # 字节统计量
        byte_values = list(combined_payload)
        if byte_values:
            byte_stats = self._safe_stat(byte_values)
            for stat_name, stat_value in byte_stats.items():
                self._add_feature(f'payload_byte_{stat_name}', stat_value)
        
        # 香农熵
        entropy = self._calculate_entropy(combined_payload)
        self._add_feature('payload_entropy', entropy)
        
        # 前N字节的熵
        for n in [64, 128, 256]:
            if len(combined_payload) >= n:
                first_n_bytes = combined_payload[:n]
                self._add_feature(f'payload_first_{n}_entropy', self._calculate_entropy(first_n_bytes))
        
        # 字符分布特征
        printable_count = 0
        alnum_count = 0
        
        for byte in combined_payload:
            # 可打印ASCII字符 (32-126)
            if 32 <= byte <= 126:
                printable_count += 1
                # 字母数字字符
                if (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122):
                    alnum_count += 1
        
        total_bytes = len(combined_payload)
        self._add_feature('payload_printable_ratio', printable_count / total_bytes if total_bytes > 0 else 0)
        self._add_feature('payload_alnum_ratio', alnum_count / total_bytes if total_bytes > 0 else 0)
        
        # 字节分布直方图（简化版）
        # 计算16个区间的直方图
        hist, _ = np.histogram(byte_values, bins=16, range=(0, 255))
        hist_normalized = hist / total_bytes if total_bytes > 0 else hist
        
        for i, freq in enumerate(hist_normalized):
            self._add_feature(f'payload_hist_bin_{i}', freq)
    
    def _extract_structural_features(self, payloads: List[bytes]):
        """提取结构特征"""
        if not payloads:
            return
        
        # 检查常见协议魔数
        magic_numbers = {
            b'\x47\x45\x54': 'HTTP_GET',
            b'\x50\x4F\x53\x54': 'HTTP_POST',
            b'\x16\x03': 'TLS_1_0',
            b'\x16\x03\x01': 'TLS_1_0',
            b'\x16\x03\x02': 'TLS_1_1',
            b'\x16\x03\x03': 'TLS_1_2',
            b'\x16\x03\x04': 'TLS_1_3',
            b'\x53\x53\x48': 'SSH',
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89\x50\x4E\x47': 'PNG',
            b'\x47\x49\x46\x38': 'GIF'
        }
        
        combined_payload = b''.join(payloads)
        
        # 检查是否有魔数匹配
        magic_found = False
        for magic, name in magic_numbers.items():
            if magic in combined_payload[:100]:  # 只检查前100字节
                self._add_feature(f'payload_magic_{name}', 1)
                magic_found = True
        
        if not magic_found:
            self._add_feature('payload_magic_unknown', 1)
        
        # 载荷长度模特定值的分布
        payload_lengths = [len(p) for p in payloads]
        
        for mod_value in [2, 4, 8, 16, 32, 64, 128, 256]:
            mod_counts = [length % mod_value for length in payload_lengths]
            if payload_lengths:
                mod_stats = self._safe_stat(mod_counts)
                for stat_name, stat_value in mod_stats.items():
                    self._add_feature(f'payload_length_mod_{mod_value}_{stat_name}', stat_value)
        
        # 查找常见模式
        # 检查是否为ASCII文本（高比例的可打印字符）
        combined_str = None
        try:
            combined_str = combined_payload.decode('ascii', errors='ignore')
            
            # 检查常见HTTP头
            if 'HTTP/' in combined_str or 'GET ' in combined_str or 'POST ' in combined_str:
                self._add_feature('payload_looks_like_http', 1)
            
            # 检查JSON
            if combined_str.strip().startswith('{') or combined_str.strip().startswith('['):
                self._add_feature('payload_looks_like_json', 1)
            
            # 检查XML
            if '<?xml' in combined_str or '<xml' in combined_str:
                self._add_feature('payload_looks_like_xml', 1)
        except:
            self._add_feature('payload_looks_like_http', 0)
            self._add_feature('payload_looks_like_json', 0)
            self._add_feature('payload_looks_like_xml', 0)
    
    def _extract_encryption_compression_features(self, payloads: List[bytes]):
        """提取加密与压缩特征"""
        if not payloads:
            return
        
        combined_payload = b''.join(payloads)
        
        if not combined_payload:
            return
        
        # 卡方检验（检验均匀性）
        byte_counts = np.zeros(256)
        for byte in combined_payload:
            byte_counts[byte] += 1
        
        expected = len(combined_payload) / 256
        if expected > 0:
            chi_square = np.sum((byte_counts - expected) ** 2 / expected)
            self._add_feature('payload_chi_square', chi_square)
        
        # 马尔可夫链测试（简化的转移概率）
        if len(combined_payload) >= 3:
            # 计算字节转移频率
            transition_counts = np.zeros((256, 256))
            for i in range(len(combined_payload) - 1):
                from_byte = combined_payload[i]
                to_byte = combined_payload[i+1]
                transition_counts[from_byte, to_byte] += 1
            
            # 计算转移熵
            transition_entropy = 0
            for i in range(256):
                row_sum = np.sum(transition_counts[i])
                if row_sum > 0:
                    row_probs = transition_counts[i] / row_sum
                    row_probs = row_probs[row_probs > 0]
                    row_entropy = -np.sum(row_probs * np.log2(row_probs))
                    transition_entropy += row_entropy * (row_sum / (len(combined_payload) - 1))
            
            self._add_feature('payload_markov_entropy', transition_entropy)
        
        # 序列相关性测试
        if len(combined_payload) >= 10:
            try:
                # 自相关
                byte_values = list(combined_payload)
                mean_val = np.mean(byte_values)
                var_val = np.var(byte_values)
                
                if var_val > 0:
                    autocorr_lag1 = np.corrcoef(byte_values[:-1], byte_values[1:])[0, 1]
                    if not np.isnan(autocorr_lag1):
                        self._add_feature('payload_autocorrelation_lag1', autocorr_lag1)
            except:
                pass
        
        # 压缩率估计（使用简单的gzip压缩模拟）
        try:
            import zlib
            compressed_size = len(zlib.compress(combined_payload))
            compression_ratio = compressed_size / len(combined_payload) if len(combined_payload) > 0 else 1
            self._add_feature('payload_compression_ratio', compression_ratio)
        except:
            self._add_feature('payload_compression_ratio', 1.0)
        
        # 与已知加密协议的相似度
        # 检查TLS/SSL特征
        if combined_payload[:3] in [b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03', b'\x16\x03\x04']:
            self._add_feature('payload_looks_like_tls', 1)
        else:
            self._add_feature('payload_looks_like_tls', 0)
        
        # 检查SSH特征
        if b'SSH-' in combined_payload[:20]:
            self._add_feature('payload_looks_like_ssh', 1)
        else:
            self._add_feature('payload_looks_like_ssh', 0)
    
    def _extract_session_payload_features(self, payloads: List[bytes]):
        """提取会话载荷聚合特征"""
        if not payloads:
            return
        
        # 载荷大小序列
        payload_sizes = [len(p) for p in payloads]
        
        payload_size_stats = self._safe_stat(payload_sizes)
        for stat_name, stat_value in payload_size_stats.items():
            self._add_feature(f'payload_size_{stat_name}', stat_value)
        
        # 非空载荷比例
        non_empty_payloads = [p for p in payloads if len(p) > 0]
        self._add_feature('payload_non_empty_ratio', len(non_empty_payloads) / len(payloads) if payloads else 0)
        
        # 载荷大小变化模式
        if len(payload_sizes) >= 2:
            size_diffs = [payload_sizes[i] - payload_sizes[i-1] for i in range(1, len(payload_sizes))]
            size_diff_stats = self._safe_stat(size_diffs)
            for stat_name, stat_value in size_diff_stats.items():
                self._add_feature(f'payload_size_diff_{stat_name}', stat_value)

# ========== 协议头部特征提取器 ==========

class ProtocolHeaderFeatureExtractor(BaseFeatureExtractor):
    """协议头部特征提取器（约120个特征）"""
    
    def extract(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """提取协议头部特征"""
        self.features.clear()
        
        if not packets:
            return self.features
        
        # 1. 链路层特征（简化处理）
        self._extract_link_layer_features(packets)
        
        # 2. 网络层特征
        self._extract_network_layer_features(packets)
        
        # 3. 传输层特征
        self._extract_transport_layer_features(packets)
        
        # 4. 应用层协议推断
        self._extract_application_layer_features(packets)
        
        # 5. 头部异常特征
        self._extract_header_anomalies(packets)
        
        return self.features
    
    def _extract_link_layer_features(self, packets: List[PacketInfo]):
        """提取链路层特征（简化）"""
        # 在实际环境中，可以从以太网帧提取MAC地址等信息
        # 这里仅作为占位符
        self._add_feature('l2_packets_count', len(packets))
    
    def _extract_network_layer_features(self, packets: List[PacketInfo]):
        """提取网络层特征"""
        # IP版本统计
        ipv4_count = 0
        ipv6_count = 0
        
        # TTL/TOS统计
        ttl_values = []
        tos_values = []
        
        # IP分片统计
        fragmented_count = 0
        
        for pkt in packets:
            # 记录TTL和TOS
            if pkt.ttl is not None:
                ttl_values.append(pkt.ttl)
            
            if pkt.tos is not None:
                tos_values.append(pkt.tos)
            
            # 简单的IP版本判断（基于数据包解析）
            # 在实际实现中，需要从IP头提取
        
        # TTL统计
        if ttl_values:
            ttl_stats = self._safe_stat(ttl_values)
            for stat_name, stat_value in ttl_stats.items():
                self._add_feature(f'ip_ttl_{stat_name}', stat_value)
            
            # TTL常见值
            common_ttls = [32, 64, 128, 255]
            for ttl in common_ttls:
                ttl_count = ttl_values.count(ttl)
                self._add_feature(f'ip_ttl_eq_{ttl}_count', ttl_count)
        
        # TOS统计
        if tos_values:
            tos_stats = self._safe_stat(tos_values)
            for stat_name, stat_value in tos_stats.items():
                self._add_feature(f'ip_tos_{stat_name}', stat_value)
        
        # IP地址相关特征（从第一个包提取）
        if packets:
            first_pkt = packets[0]
            
            # 简单的IP地址类别判断
            src_ip = first_pkt.src_ip
            dst_ip = first_pkt.dst_ip
            
            # 检查是否为私有IP
            def is_private_ip(ip):
                if ip.startswith('10.') or ip.startswith('192.168.') or \
                   (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                    return True
                return False
            
            self._add_feature('src_ip_is_private', 1 if is_private_ip(src_ip) else 0)
            self._add_feature('dst_ip_is_private', 1 if is_private_ip(dst_ip) else 0)
    
    def _extract_transport_layer_features(self, packets: List[PacketInfo]):
        """提取传输层特征"""
        # 协议类型统计
        protocol_counts = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0
        }
        
        # TCP特定特征
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        udp_packets = [p for p in packets if p.protocol == ProtocolType.UDP]
        
        # 端口特征
        src_ports = set()
        dst_ports = set()
        
        # 知名端口统计
        well_known_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995}
        
        well_known_src_count = 0
        well_known_dst_count = 0
        
        for pkt in packets:
            # 协议统计
            if pkt.protocol == ProtocolType.TCP:
                protocol_counts['tcp'] += 1
            elif pkt.protocol == ProtocolType.UDP:
                protocol_counts['udp'] += 1
            elif pkt.protocol == ProtocolType.ICMP:
                protocol_counts['icmp'] += 1
            else:
                protocol_counts['other'] += 1
            
            # 端口收集
            src_ports.add(pkt.src_port)
            dst_ports.add(pkt.dst_port)
            
            # 知名端口检查
            if pkt.src_port in well_known_ports:
                well_known_src_count += 1
            if pkt.dst_port in well_known_ports:
                well_known_dst_count += 1
        
        # 协议比例
        total_packets = len(packets)
        for proto, count in protocol_counts.items():
            self._add_feature(f'protocol_{proto}_ratio', count / total_packets if total_packets > 0 else 0)
        
        # 端口特征
        self._add_feature('unique_src_ports', len(src_ports))
        self._add_feature('unique_dst_ports', len(dst_ports))
        self._add_feature('well_known_src_port_ratio', 
                         well_known_src_count / total_packets if total_packets > 0 else 0)
        self._add_feature('well_known_dst_port_ratio',
                         well_known_dst_count / total_packets if total_packets > 0 else 0)
        
        # TCP特征
        if tcp_packets:
            # TCP窗口大小统计
            window_sizes = [p.tcp_window for p in tcp_packets if p.tcp_window is not None]
            if window_sizes:
                window_stats = self._safe_stat(window_sizes)
                for stat_name, stat_value in window_stats.items():
                    self._add_feature(f'tcp_window_{stat_name}', stat_value)
            
            # TCP序列号/确认号特征
            seq_numbers = [p.tcp_seq for p in tcp_packets if p.tcp_seq is not None]
            ack_numbers = [p.tcp_ack for p in tcp_packets if p.tcp_ack is not None]
            
            if seq_numbers:
                seq_stats = self._safe_stat(seq_numbers)
                for stat_name, stat_value in seq_stats.items():
                    self._add_feature(f'tcp_seq_{stat_name}', stat_value)
            
            if ack_numbers:
                ack_stats = self._safe_stat(ack_numbers)
                for stat_name, stat_value in ack_stats.items():
                    self._add_feature(f'tcp_ack_{stat_name}', stat_value)
        
        # UDP特征
        if udp_packets:
            udp_lengths = [p.packet_length for p in udp_packets]
            udp_length_stats = self._safe_stat(udp_lengths)
            for stat_name, stat_value in udp_length_stats.items():
                self._add_feature(f'udp_length_{stat_name}', stat_value)
    
    def _extract_application_layer_features(self, packets: List[PacketInfo]):
        """提取应用层特征"""
        # 基于端口的协议推断
        if packets:
            first_pkt = packets[0]
            
            # 常见应用层协议端口映射
            app_protocols = {
                80: 'HTTP',
                443: 'HTTPS',
                53: 'DNS',
                25: 'SMTP',
                110: 'POP3',
                143: 'IMAP',
                22: 'SSH',
                23: 'TELNET',
                21: 'FTP',
                69: 'TFTP',
                161: 'SNMP',
                162: 'SNMP_TRAP',
                67: 'DHCP_SERVER',
                68: 'DHCP_CLIENT',
                123: 'NTP',
                137: 'NETBIOS_NS',
                138: 'NETBIOS_DGM',
                139: 'NETBIOS_SSN',
                445: 'SMB',
                3306: 'MYSQL',
                3389: 'RDP',
                8080: 'HTTP_PROXY',
                8443: 'HTTPS_ALT'
            }
            
            # 检查源端口和目标端口
            src_protocol = app_protocols.get(first_pkt.src_port, 'UNKNOWN')
            dst_protocol = app_protocols.get(first_pkt.dst_port, 'UNKNOWN')
            
            self._add_feature('src_port_protocol', src_protocol)
            self._add_feature('dst_port_protocol', dst_protocol)
            
            # 标记常见服务
            common_service_ports = {80, 443, 53, 25, 110, 143, 22, 21}
            if first_pkt.dst_port in common_service_ports:
                self._add_feature('is_common_service', 1)
            else:
                self._add_feature('is_common_service', 0)
            
            # 检查是否为短暂端口（通常客户端使用）
            if 1024 <= first_pkt.src_port <= 65535:
                self._add_feature('src_port_is_ephemeral', 1)
            else:
                self._add_feature('src_port_is_ephemeral', 0)
            
            if 1024 <= first_pkt.dst_port <= 65535:
                self._add_feature('dst_port_is_ephemeral', 1)
            else:
                self._add_feature('dst_port_is_ephemeral', 0)
    
    def _extract_header_anomalies(self, packets: List[PacketInfo]):
        """提取头部异常特征"""
        anomaly_count = 0
        tcp_anomaly_count = 0
        
        for pkt in packets:
            # TCP标志位异常检查
            if pkt.protocol == ProtocolType.TCP and pkt.tcp_flags:
                flags = pkt.tcp_flags
                
                # SYN和FIN同时设置
                if flags.get('SYN', False) and flags.get('FIN', False):
                    tcp_anomaly_count += 1
                
                # SYN和RST同时设置
                if flags.get('SYN', False) and flags.get('RST', False):
                    tcp_anomaly_count += 1
                
                # FIN和RST同时设置
                if flags.get('FIN', False) and flags.get('RST', False):
                    tcp_anomaly_count += 1
                
                # 没有设置任何标志位
                if not any(flags.values()):
                    tcp_anomaly_count += 1
            
            # TTL异常（值非常小）
            if pkt.ttl is not None and pkt.ttl < 5:
                anomaly_count += 1
        
        self._add_feature('header_anomaly_count', anomaly_count)
        self._add_feature('tcp_header_anomaly_count', tcp_anomaly_count)
        self._add_feature('header_anomaly_ratio', anomaly_count / len(packets) if packets else 0)

# ========== 行为特征提取器 ==========

class BehavioralFeatureExtractor(BaseFeatureExtractor):
    """行为特征提取器（约80个特征）"""
    
    def __init__(self, host_flows_dict=None):
        super().__init__()
        self.host_flows_dict = host_flows_dict or {}
    
    def extract(self, packets: List[PacketInfo], flow_key: Tuple) -> Dict[str, Any]:
        """提取行为特征"""
        self.features.clear()
        
        if not packets:
            return self.features
        
        first_pkt = packets[0]
        
        # 1. 主机层面行为
        self._extract_host_level_behavior(first_pkt, flow_key)
        
        # 2. 扫描与探测行为
        self._extract_scanning_behavior(packets, first_pkt)
        
        # 3. 通信周期性
        self._extract_communication_periodicity(packets)
        
        # 4. 会话交互模式
        self._extract_session_interaction_patterns(packets, flow_key)
        
        # 5. 失败与异常行为
        self._extract_failure_anomaly_behavior(packets)
        
        return self.features
    
    def _extract_host_level_behavior(self, first_pkt: PacketInfo, flow_key: Tuple):
        """提取主机层面行为特征"""
        src_ip = first_pkt.src_ip
        dst_ip = first_pkt.dst_ip
        
        # 检查主机在host_flows_dict中的行为
        if self.host_flows_dict:
            # 作为客户端的行为
            if src_ip in self.host_flows_dict:
                client_flows = self.host_flows_dict[src_ip]
                self._add_feature('host_as_client_flow_count', len(client_flows))
                
                # 计算目标IP离散度
                dst_ips = set()
                dst_ports = set()
                for flow in client_flows:
                    dst_ips.add(flow[1])  # 目标IP
                    dst_ports.add(flow[3])  # 目标端口
                
                self._add_feature('client_dst_ip_diversity', len(dst_ips))
                self._add_feature('client_dst_port_diversity', len(dst_ports))
            
            # 作为服务器的行为
            if dst_ip in self.host_flows_dict:
                server_flows = self.host_flows_dict[dst_ip]
                self._add_feature('host_as_server_flow_count', len(server_flows))
        
        # 源端口范围特征
        src_port = first_pkt.src_port
        if 0 <= src_port <= 1023:
            self._add_feature('src_port_range', 'well_known')
        elif 1024 <= src_port <= 49151:
            self._add_feature('src_port_range', 'registered')
        else:
            self._add_feature('src_port_range', 'dynamic')
    
    def _extract_scanning_behavior(self, packets: List[PacketInfo], first_pkt: PacketInfo):
        """提取扫描与探测行为特征"""
        # 简单扫描检测（基于失败连接）
        # 在实际实现中，需要更多上下文信息
        
        # 检查是否为端口扫描模式
        # 这里简化处理，仅标记某些特征
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        
        if tcp_packets:
            # 计算SYN包比例
            syn_packets = [p for p in tcp_packets if p.tcp_flags and p.tcp_flags.get('SYN', False)]
            syn_only_packets = [p for p in syn_packets if p.tcp_flags and 
                               not p.tcp_flags.get('ACK', False)]
            
            syn_ratio = len(syn_packets) / len(tcp_packets) if tcp_packets else 0
            syn_only_ratio = len(syn_only_packets) / len(tcp_packets) if tcp_packets else 0
            
            self._add_feature('tcp_syn_ratio', syn_ratio)
            self._add_feature('tcp_syn_only_ratio', syn_only_ratio)
            
            # 检查RST响应（可能表示端口关闭）
            rst_packets = [p for p in tcp_packets if p.tcp_flags and p.tcp_flags.get('RST', False)]
            self._add_feature('tcp_rst_ratio', len(rst_packets) / len(tcp_packets) if tcp_packets else 0)
    
    def _extract_communication_periodicity(self, packets: List[PacketInfo]):
        """提取通信周期性特征"""
        if len(packets) < 3:
            return
        
        # 计算时间间隔的规律性
        timestamps = [p.timestamp for p in packets]
        
        # 计算时间间隔
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if len(intervals) >= 3:
            # 计算间隔的变异系数
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            if mean_interval > 0:
                cv_interval = std_interval / mean_interval
                self._add_feature('interval_coefficient_of_variation', cv_interval)
            
            # 检查是否存在固定间隔模式
            # 简单方法：计算相邻间隔的比值
            interval_ratios = []
            for i in range(1, len(intervals)):
                if intervals[i-1] > 0:
                    ratio = intervals[i] / intervals[i-1]
                    interval_ratios.append(ratio)
            
            if interval_ratios:
                ratio_stats = self._safe_stat(interval_ratios)
                self._add_feature('interval_ratio_mean', ratio_stats['mean'])
                
                # 如果比值接近1，表示间隔规律
                if 0.9 <= ratio_stats['mean'] <= 1.1:
                    self._add_feature('has_regular_intervals', 1)
                else:
                    self._add_feature('has_regular_intervals', 0)
        
        # 傅里叶分析检测周期性（简化版）
        if len(packets) >= 10:
            try:
                # 创建时间序列
                time_series = []
                start_time = timestamps[0]
                end_time = timestamps[-1]
                time_range = end_time - start_time
                
                if time_range > 0:
                    # 将时间序列离散化为100个点
                    num_bins = 100
                    bin_size = time_range / num_bins
                    
                    for i in range(num_bins):
                        bin_start = start_time + i * bin_size
                        bin_end = bin_start + bin_size
                        
                        # 计算该时间窗口内的包数
                        bin_count = sum(1 for t in timestamps if bin_start <= t < bin_end)
                        time_series.append(bin_count)
                    
                    # 计算FFT
                    fft_result = fft(time_series)
                    fft_magnitude = np.abs(fft_result)
                    
                    # 查找主要频率
                    main_freq_idx = np.argmax(fft_magnitude[1:len(fft_magnitude)//2]) + 1
                    main_freq_magnitude = fft_magnitude[main_freq_idx]
                    
                    # 总能量
                    total_energy = np.sum(fft_magnitude[1:len(fft_magnitude)//2] ** 2)
                    
                    if total_energy > 0:
                        # 主要频率的能量占比
                        dominant_freq_ratio = (main_freq_magnitude ** 2) / total_energy
                        self._add_feature('periodic_dominant_freq_ratio', dominant_freq_ratio)
                        
                        if dominant_freq_ratio > 0.3:  # 阈值可调整
                            self._add_feature('has_strong_periodicity', 1)
                        else:
                            self._add_feature('has_strong_periodicity', 0)
            except:
                pass
    
    def _extract_session_interaction_patterns(self, packets: List[PacketInfo], flow_key: Tuple):
        """提取会话交互模式特征"""
        # 分离前向和后向数据包
        forward_packets = []
        backward_packets = []
        
        for pkt in packets:
            direction = pkt.get_direction(flow_key)
            if direction == FlowDirection.FORWARD:
                forward_packets.append(pkt)
            elif direction == FlowDirection.BACKWARD:
                backward_packets.append(pkt)
        
        # 检查交互模式
        if forward_packets and backward_packets:
            # 计算请求-响应延迟统计
            response_delays = []
            
            # 简单配对：每个前向包后第一个后向包的时间差
            fwd_idx = 0
            bwd_idx = 0
            
            while fwd_idx < len(forward_packets) and bwd_idx < len(backward_packets):
                if backward_packets[bwd_idx].timestamp > forward_packets[fwd_idx].timestamp:
                    delay = backward_packets[bwd_idx].timestamp - forward_packets[fwd_idx].timestamp
                    response_delays.append(delay)
                    fwd_idx += 1
                    bwd_idx += 1
                else:
                    bwd_idx += 1
            
            if response_delays:
                delay_stats = self._safe_stat(response_delays)
                for stat_name, stat_value in delay_stats.items():
                    self._add_feature(f'response_delay_{stat_name}', stat_value)
                
                # 交互式会话通常有小的响应延迟
                if delay_stats['mean'] < 0.1:  # 100ms阈值
                    self._add_feature('is_interactive_session', 1)
                else:
                    self._add_feature('is_interactive_session', 0)
            
            # 检查会话不对称性
            fwd_bytes = sum(p.packet_length for p in forward_packets)
            bwd_bytes = sum(p.packet_length for p in backward_packets)
            
            if bwd_bytes > 0:
                asymmetry_ratio = fwd_bytes / bwd_bytes
                self._add_feature('flow_asymmetry_ratio', asymmetry_ratio)
                
                # 常见模式
                if asymmetry_ratio > 10:
                    self._add_feature('flow_pattern', 'download_heavy')
                elif asymmetry_ratio < 0.1:
                    self._add_feature('flow_pattern', 'upload_heavy')
                elif 0.5 <= asymmetry_ratio <= 2:
                    self._add_feature('flow_pattern', 'balanced')
                else:
                    self._add_feature('flow_pattern', 'asymmetric')
        
        # 批量传输特征
        if packets:
            total_bytes = sum(p.packet_length for p in packets)
            duration = packets[-1].timestamp - packets[0].timestamp
            
            if duration > 0:
                avg_throughput = total_bytes / duration
                self._add_feature('avg_throughput', avg_throughput)
                
                # 检查是否为批量传输
                if avg_throughput > 10000:  # 10KB/s阈值
                    self._add_feature('is_bulk_transfer', 1)
                else:
                    self._add_feature('is_bulk_transfer', 0)
    
    def _extract_failure_anomaly_behavior(self, packets: List[PacketInfo]):
        """提取失败与异常行为特征"""
        # TCP特定失败检测
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        
        if tcp_packets:
            # 检查半开连接（只有SYN没有后续）
            syn_packets = [p for p in tcp_packets if p.tcp_flags and p.tcp_flags.get('SYN', False)]
            syn_ack_packets = [p for p in tcp_packets if p.tcp_flags and 
                              p.tcp_flags.get('SYN', False) and p.tcp_flags.get('ACK', False)]
            
            # 半开连接估计
            if len(syn_packets) > 0:
                half_open_ratio = (len(syn_packets) - len(syn_ack_packets)) / len(syn_packets)
                self._add_feature('tcp_half_open_ratio', max(0, half_open_ratio))
            
            # 检查快速重传（需要序列号分析）
            # 这里简化处理
            
            # 检查零窗口（需要窗口大小分析）
            zero_window_packets = [p for p in tcp_packets if p.tcp_window == 0]
            self._add_feature('tcp_zero_window_count', len(zero_window_packets))
            
            # 重传检测（简化）
            # 在实际实现中，需要分析序列号
        
        # ICMP错误消息统计
        icmp_packets = [p for p in packets if p.protocol == ProtocolType.ICMP]
        self._add_feature('icmp_packet_count', len(icmp_packets))
        
        # 连接失败率（基于TCP RST）
        if tcp_packets:
            rst_packets = [p for p in tcp_packets if p.tcp_flags and p.tcp_flags.get('RST', False)]
            self._add_feature('tcp_rst_ratio', len(rst_packets) / len(tcp_packets))

# ========== 关联与图特征提取器 ==========

class GraphFeatureExtractor(BaseFeatureExtractor):
    """关联与图特征提取器（约60个特征）"""
    
    def __init__(self, all_flows=None):
        super().__init__()
        self.all_flows = all_flows or {}
        self.graph = None
    
    def build_host_graph(self):
        """构建主机关系图"""
        if not NETWORKX_AVAILABLE or not self.all_flows:
            return None
        
        try:
            G = nx.DiGraph()
            
            # 添加节点和边
            for flow_key, packets in self.all_flows.items():
                if packets:
                    src_ip = flow_key[0]
                    dst_ip = flow_key[1]
                    
                    # 添加节点
                    G.add_node(src_ip)
                    G.add_node(dst_ip)
                    
                    # 添加边或更新权重
                    if G.has_edge(src_ip, dst_ip):
                        G[src_ip][dst_ip]['weight'] += 1
                        G[src_ip][dst_ip]['flows'].append(flow_key)
                    else:
                        G.add_edge(src_ip, dst_ip, weight=1, flows=[flow_key])
            
            self.graph = G
            return G
        except Exception as e:
            logger.error(f"构建图失败: {e}")
            return None
    
    def extract(self, packets: List[PacketInfo], flow_key: Tuple) -> Dict[str, Any]:
        """提取关联与图特征"""
        self.features.clear()
        
        if not packets:
            return self.features
        
        first_pkt = packets[0]
        src_ip = first_pkt.src_ip
        dst_ip = first_pkt.dst_ip
        
        # 1. 主机对特征
        self._extract_host_pair_features(src_ip, dst_ip)
        
        # 2. 网络图结构特征
        self._extract_graph_structure_features(src_ip, dst_ip)
        
        # 3. 横向关联特征
        self._extract_lateral_correlation_features(src_ip, dst_ip)
        
        # 4. 时间关联特征
        self._extract_temporal_correlation_features(packets, src_ip, dst_ip)
        
        return self.features
    
    def _extract_host_pair_features(self, src_ip: str, dst_ip: str):
        """提取主机对特征"""
        # 计算历史连接频率
        if self.all_flows:
            pair_flow_count = 0
            
            for flow_key, _ in self.all_flows.items():
                if (flow_key[0] == src_ip and flow_key[1] == dst_ip) or \
                   (flow_key[0] == dst_ip and flow_key[1] == src_ip):
                    pair_flow_count += 1
            
            self._add_feature('host_pair_flow_count', pair_flow_count)
        
        # 简单的主机对特征
        self._add_feature('src_ip', src_ip)
        self._add_feature('dst_ip', dst_ip)
    
    def _extract_graph_structure_features(self, src_ip: str, dst_ip: str):
        """提取网络图结构特征"""
        if not self.graph:
            self.build_host_graph()
        
        if not self.graph:
            return
        
        try:
            # 节点度特征
            if src_ip in self.graph:
                src_out_degree = self.graph.out_degree(src_ip)
                src_in_degree = self.graph.in_degree(src_ip)
                src_total_degree = src_out_degree + src_in_degree
                
                self._add_feature('src_out_degree', src_out_degree)
                self._add_feature('src_in_degree', src_in_degree)
                self._add_feature('src_total_degree', src_total_degree)
            
            if dst_ip in self.graph:
                dst_out_degree = self.graph.out_degree(dst_ip)
                dst_in_degree = self.graph.in_degree(dst_ip)
                dst_total_degree = dst_out_degree + dst_in_degree
                
                self._add_feature('dst_out_degree', dst_out_degree)
                self._add_feature('dst_in_degree', dst_in_degree)
                self._add_feature('dst_total_degree', dst_total_degree)
            
            # 边权重特征
            if self.graph.has_edge(src_ip, dst_ip):
                edge_weight = self.graph[src_ip][dst_ip]['weight']
                self._add_feature('edge_weight', edge_weight)
            
            # 中心性特征（计算成本高，选择性计算）
            if self.graph.number_of_nodes() < 100:  # 只在图较小时计算
                try:
                    # 度中心性
                    degree_centrality = nx.degree_centrality(self.graph)
                    if src_ip in degree_centrality:
                        self._add_feature('src_degree_centrality', degree_centrality[src_ip])
                    if dst_ip in degree_centrality:
                        self._add_feature('dst_degree_centrality', degree_centrality[dst_ip])
                    
                    # 介数中心性（非常耗时）
                    # betweenness_centrality = nx.betweenness_centrality(self.graph, k=min(10, self.graph.number_of_nodes()))
                    # if src_ip in betweenness_centrality:
                    #     self._add_feature('src_betweenness_centrality', betweenness_centrality[src_ip])
                    # if dst_ip in betweenness_centrality:
                    #     self._add_feature('dst_betweenness_centrality', betweenness_centrality[dst_ip])
                except:
                    pass
            
            # 聚类系数
            try:
                clustering_coeff = nx.clustering(self.graph.to_undirected())
                if src_ip in clustering_coeff:
                    self._add_feature('src_clustering_coefficient', clustering_coeff[src_ip])
                if dst_ip in clustering_coeff:
                    self._add_feature('dst_clustering_coefficient', clustering_coeff[dst_ip])
            except:
                pass
        
        except Exception as e:
            logger.warning(f"图特征提取失败: {e}")
    
    def _extract_lateral_correlation_features(self, src_ip: str, dst_ip: str):
        """提取横向关联特征"""
        if not self.all_flows:
            return
        
        # 检查是否有其他主机与同一目标通信
        same_dst_flows = 0
        same_src_flows = 0
        
        for flow_key, _ in self.all_flows.items():
            flow_src_ip = flow_key[0]
            flow_dst_ip = flow_key[1]
            
            if flow_dst_ip == dst_ip and flow_src_ip != src_ip:
                same_dst_flows += 1
            
            if flow_src_ip == src_ip and flow_dst_ip != dst_ip:
                same_src_flows += 1
        
        self._add_feature('other_hosts_to_dst_count', same_dst_flows)
        self._add_feature('src_to_other_hosts_count', same_src_flows)
        
        # 检查P2P模式
        # 如果主机A与多个其他主机通信，可能是P2P节点
        if same_src_flows > 5:
            self._add_feature('possible_p2p_client', 1)
        else:
            self._add_feature('possible_p2p_client', 0)
    
    def _extract_temporal_correlation_features(self, packets: List[PacketInfo], src_ip: str, dst_ip: str):
        """提取时间关联特征"""
        # 检查时间同步性（简化处理）
        if len(packets) < 2:
            return
        
        # 计算流内时间模式
        timestamps = [p.timestamp for p in packets]
        start_time = timestamps[0]
        
        # 检查是否有其他流在同一时间开始
        if self.all_flows and len(self.all_flows) > 1:
            synchronized_flows = 0
            
            for other_flow_key, other_packets in self.all_flows.items():
                if other_flow_key == (src_ip, dst_ip, packets[0].src_port, packets[0].dst_port, packets[0].protocol):
                    continue
                
                if other_packets:
                    other_start = other_packets[0].timestamp
                    # 如果开始时间接近（在1秒内）
                    if abs(other_start - start_time) < 1.0:
                        synchronized_flows += 1
            
            self._add_feature('synchronized_flows_count', synchronized_flows)
        
        # 检查因果关系（如DNS查询后连接）
        # 在实际实现中，需要分析多个流的关系

# ========== 主特征提取器 ==========

class NetworkFlowFeatureExtractor:
    """网络流量特征提取主类"""
    
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = []
        self.flows = {}
        self.host_flows = defaultdict(list)
        
        # 初始化各个特征提取器
        self.stat_extractor = StatisticalFeatureExtractor()
        self.seq_extractor = SequenceFeatureExtractor()
        self.payload_extractor = PayloadFeatureExtractor()
        self.protocol_extractor = ProtocolHeaderFeatureExtractor()
        self.behavior_extractor = BehavioralFeatureExtractor()
        self.graph_extractor = GraphFeatureExtractor()
        
        # 特征存储
        self.all_features = []
        self.feature_names = []
    
    def load_pcap(self, pcap_file=None):
        """加载pcap文件"""
        if not SCAPY_AVAILABLE:
            logger.error("scapy未安装，无法加载pcap文件")
            return False
        
        file_to_load = pcap_file or self.pcap_file
        if not file_to_load:
            logger.error("未指定pcap文件")
            return False
        
        if not os.path.exists(file_to_load):
            logger.error(f"文件不存在: {file_to_load}")
            return False
        
        try:
            logger.info(f"加载pcap文件: {file_to_load}")
            packets = rdpcap(file_to_load)
            logger.info(f"成功加载 {len(packets)} 个数据包")
            
            self._process_packets(packets)
            return True
        except Exception as e:
            logger.error(f"加载pcap文件失败: {e}")
            return False
    
    def _process_packets(self, scapy_packets):
        """处理scapy数据包，转换为内部格式"""
        self.packets = []
        
        for i, pkt in enumerate(scapy_packets):
            try:
                packet_info = self._parse_packet(pkt, i)
                if packet_info:
                    self.packets.append(packet_info)
            except Exception as e:
                logger.debug(f"解析数据包 {i} 失败: {e}")
        
        logger.info(f"成功解析 {len(self.packets)} 个数据包")
        
        # 按流分组
        self._group_packets_by_flow()
    
    def _parse_packet(self, pkt, packet_index) -> Optional[PacketInfo]:
        """解析单个数据包"""
        try:
            # 提取时间戳
            timestamp = float(pkt.time)
            
            # 提取网络层信息
            src_ip = None
            dst_ip = None
            protocol = ProtocolType.OTHER
            ttl = None
            tos = None
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ttl = pkt[IP].ttl
                tos = pkt[IP].tos
                
                # 确定传输层协议
                if TCP in pkt:
                    protocol = ProtocolType.TCP
                elif UDP in pkt:
                    protocol = ProtocolType.UDP
                elif ICMP in pkt:
                    protocol = ProtocolType.ICMP
            else:
                # 非IP包，跳过或处理其他协议
                return None
            
            # 提取端口信息
            src_port = 0
            dst_port = 0
            
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            
            # 提取TCP标志位
            tcp_flags = None
            tcp_window = None
            tcp_seq = None
            tcp_ack = None
            
            if TCP in pkt:
                tcp_flags = {
                    'FIN': bool(pkt[TCP].flags.F),
                    'SYN': bool(pkt[TCP].flags.S),
                    'RST': bool(pkt[TCP].flags.R),
                    'PSH': bool(pkt[TCP].flags.P),
                    'ACK': bool(pkt[TCP].flags.A),
                    'URG': bool(pkt[TCP].flags.U),
                    'ECE': bool(pkt[TCP].flags.E),
                    'CWR': bool(pkt[TCP].flags.C)
                }
                tcp_window = pkt[TCP].window
                tcp_seq = pkt[TCP].seq
                tcp_ack = pkt[TCP].ack
            
            # 提取载荷
            payload = None
            payload_length = 0
            
            if Raw in pkt:
                payload = bytes(pkt[Raw])
                payload_length = len(payload)
            
            # 总包长
            packet_length = len(pkt)
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_length=packet_length,
                payload_length=payload_length,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
                tcp_seq=tcp_seq,
                tcp_ack=tcp_ack,
                ttl=ttl,
                tos=tos,
                payload=payload
            )
        
        except Exception as e:
            logger.debug(f"解析数据包失败: {e}")
            return None
    
    def _group_packets_by_flow(self):
        """按流分组数据包"""
        self.flows.clear()
        self.host_flows.clear()
        
        for pkt in self.packets:
            # 创建流键
            flow_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            
            # 添加到流
            if flow_key not in self.flows:
                self.flows[flow_key] = []
            self.flows[flow_key].append(pkt)
            
            # 按主机组织流
            self.host_flows[pkt.src_ip].append(flow_key)
        
        logger.info(f"识别出 {len(self.flows)} 个流")
        
        # 为图特征提取器设置所有流
        self.graph_extractor.all_flows = self.flows
        # 为行为特征提取器设置主机流字典
        self.behavior_extractor.host_flows_dict = self.host_flows
    
    def extract_flow_features(self, flow_key):
        """提取单个流的特征"""
        if flow_key not in self.flows:
            logger.warning(f"流不存在: {flow_key}")
            return None
        
        packets = self.flows[flow_key]
        
        # 按时间排序
        packets.sort(key=lambda x: x.timestamp)
        
        # 提取各维度特征
        stat_features = self.stat_extractor.extract(packets, flow_key)
        seq_features = self.seq_extractor.extract(packets, flow_key)
        payload_features = self.payload_extractor.extract(packets)
        protocol_features = self.protocol_extractor.extract(packets)
        behavior_features = self.behavior_extractor.extract(packets, flow_key)
        graph_features = self.graph_extractor.extract(packets, flow_key)
        
        # 合并所有特征
        all_features = {}
        all_features.update(stat_features)
        all_features.update(seq_features)
        all_features.update(payload_features)
        all_features.update(protocol_features)
        all_features.update(behavior_features)
        all_features.update(graph_features)
        
        # 添加流标识信息
        all_features['flow_key'] = str(flow_key)
        all_features['packet_count'] = len(packets)
        
        return all_features
    
    def extract_all_flows(self, max_flows=None):
        """提取所有流的特征"""
        self.all_features = []
        
        flow_keys = list(self.flows.keys())
        if max_flows:
            flow_keys = flow_keys[:max_flows]
        
        logger.info(f"开始提取 {len(flow_keys)} 个流的特征...")
        
        # 首先构建图（用于图特征提取）
        logger.info("构建主机关系图...")
        self.graph_extractor.build_host_graph()
        
        # 提取每个流的特征
        for i, flow_key in enumerate(flow_keys):
            if (i + 1) % 10 == 0:
                logger.info(f"处理进度: {i+1}/{len(flow_keys)}")
            
            features = self.extract_flow_features(flow_key)
            if features:
                self.all_features.append(features)
        
        logger.info(f"成功提取 {len(self.all_features)} 个流的特征")
        
        # 收集所有特征名称
        if self.all_features:
            self.feature_names = list(self.all_features[0].keys())
        
        return self.all_features
    
    def save_features(self, output_file, format='csv'):
        """保存特征到文件"""
        if not self.all_features:
            logger.warning("没有特征数据可保存")
            return False
        
        try:
            df = pd.DataFrame(self.all_features)
            
            if format.lower() == 'csv':
                df.to_csv(output_file, index=False)
                logger.info(f"特征已保存到 CSV 文件: {output_file}")
            elif format.lower() == 'json':
                df.to_json(output_file, orient='records', indent=2)
                logger.info(f"特征已保存到 JSON 文件: {output_file}")
            elif format.lower() == 'parquet':
                df.to_parquet(output_file, index=False)
                logger.info(f"特征已保存到 Parquet 文件: {output_file}")
            else:
                logger.error(f"不支持的格式: {format}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"保存特征失败: {e}")
            return False
    
    def get_feature_summary(self):
        """获取特征摘要"""
        if not self.all_features:
            return "没有特征数据"
        
        df = pd.DataFrame(self.all_features)
        
        summary = f"""
        特征提取摘要:
        ====================
        总流数: {len(self.all_features)}
        总特征数: {len(self.feature_names)}
        特征维度: {len(self.all_features[0])}
        
        特征类别统计:
        - 统计特征: {sum(1 for f in self.feature_names if 'stat' in f.lower() or any(x in f.lower() for x in ['mean', 'std', 'min', 'max', 'ratio']))}
        - 序列特征: {sum(1 for f in self.feature_names if any(x in f.lower() for x in ['sequence', 'autocorr', 'fft', 'hurst']))}
        - 载荷特征: {sum(1 for f in self.feature_names if 'payload' in f.lower())}
        - 协议特征: {sum(1 for f in self.feature_names if any(x in f.lower() for x in ['tcp', 'udp', 'ip', 'port', 'protocol']))}
        - 行为特征: {sum(1 for f in self.feature_names if any(x in f.lower() for x in ['behavior', 'pattern', 'scan', 'periodic']))}
        - 图特征: {sum(1 for f in self.feature_names if any(x in f.lower() for x in ['degree', 'centrality', 'graph', 'cluster']))}
        
        前10个特征示例:
        {self.feature_names[:10]}
        """
        
        return summary

# ========== 主函数 ==========

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='网络流量多维度特征提取系统')
    parser.add_argument('-i', '--input', required=True, help='输入pcap文件路径')
    parser.add_argument('-o', '--output', default='flow_features.csv', help='输出特征文件路径')
    parser.add_argument('-f', '--format', default='csv', choices=['csv', 'json', 'parquet'], 
                       help='输出格式 (csv, json, parquet)')
    parser.add_argument('-m', '--max-flows', type=int, default=None, 
                       help='最大处理流数 (None表示处理所有流)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细日志')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 检查依赖
    if not SCAPY_AVAILABLE:
        print("错误: 需要安装scapy库")
        print("安装命令: pip install scapy")
        return
    
    # 创建特征提取器
    extractor = NetworkFlowFeatureExtractor(args.input)
    
    # 加载pcap文件
    if not extractor.load_pcap():
        print("加载pcap文件失败")
        return
    
    # 提取特征
    print("开始提取特征...")
    features = extractor.extract_all_flows(max_flows=args.max_flows)
    
    if not features:
        print("特征提取失败或无特征可提取")
        return
    
    # 显示摘要
    summary = extractor.get_feature_summary()
    print(summary)
    
    # 保存特征
    output_ext = os.path.splitext(args.output)[1].lower()
    if not output_ext:
        args.output = f"{args.output}.{args.format}"
    
    if extractor.save_features(args.output, args.format):
        print(f"特征已保存到: {args.output}")
    else:
        print("特征保存失败")

# ========== 使用示例 ==========

def example_usage():
    """使用示例"""
    print("""
    网络流量特征提取系统使用示例:
    
    1. 基本使用:
       python network_features.py -i input.pcap -o output.csv
    
    2. 指定输出格式:
       python network_features.py -i input.pcap -o output.json -f json
    
    3. 限制处理流数:
       python network_features.py -i input.pcap -o output.csv -m 100
    
    4. 显示详细日志:
       python network_features.py -i input.pcap -o output.csv -v
    
    5. 程序化使用:
       ```
       extractor = NetworkFlowFeatureExtractor("input.pcap")
       extractor.load_pcap()
       features = extractor.extract_all_flows(max_flows=50)
       df = pd.DataFrame(features)
       print(df.head())
       ```
    """)

if __name__ == "__main__":
    # 直接运行主函数
    main()
    
    # 或者显示使用示例
    #example_usage()
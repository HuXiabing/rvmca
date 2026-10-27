from rvmca.analysis import CFG, path_to_ssa, DDG, RVFG
from rvmca.trans.prof import *
from rvmca.trans.sched import *
from rvmca.utils.file_util import *
from rvmca.config import *
import json
import os
import gc
import ijson
import time
from typing import Dict, Any, List
import traceback
import signal

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException()

def test_onecase():
    # blocks = "add a5,s2,a5\nsb zero,0(a5)" 
    # add a5,s2,a5
    # blocks = "sw t3,0(t5)\\nld t3,0(t0)\\naddi t5,zero,3\\nadd t3,t3,a7\\nsb t5,0(t3)\\nld t5,0(a4)\\nadd t5,t5,a5\\nlw s5,0(t5)\\nld t3,368(s0)\\nld s11,0(s4)\\nadd t3,t3,a5\\nlw s8,0(t3)\\nlw t3,0(s11)\\naddw t3,t3,s8".replace('\\n', '\n')
    
    # blocks = 'sw a0,0(t2)\\nld a5,0(s6)\\nsb zero,0(a5)\\nld a5,0(t6)\\nlw a4,16(a5)'.replace('\\n','\n')
    # blocks = 'lh a5,96(t5)\\ndivw t4,a2,a5\\nmulw a5,a5,t3\\nsw t4,0(t2)\\nsw a5,0(t0)'.replace('\\n','\n')
    # blocks = 'lw a5,44(s4)\\naddi s1,zero,8\\naddi a4,zero,2\\ndivw s1,a5,s1\\nremw s5,a5,a4\\nremw s1,s1,a4\\naddi s5,s5,-1\\nsltiu s5,s5,1\\naddi s1,s1,-1\\nsltiu s1,s1,1'.replace('\\n','\n')
    # blocks = "addi a5,zero,34\\nsb a5,0(s2)\\nld s1,120(sp)\\nld s3,104(sp)\\nld s5,88(sp)\\nld s8,64(sp)\\nld s9,56(sp)\\nld s10,48(sp)\\nld s11,40(sp)\\naddi s2,s2,1\\nsb zero,0(s2)\\nld a5,0(s6)\\nsub a0,s2,s4\\nadd s7,a0,s7\\nsd s7,8(a5)\\nld ra,136(sp)\\nld s0,128(sp)\\nld s2,112(sp)\\nld s4,96(sp)\\nld s6,80(sp)\\nld s7,72(sp)\\naddiw a0,a0,0\\naddi sp,sp,144".replace('\\n', '\n')
    # blocks = "lw a5,-4(s5)\\nsd a0,1028(s5)"
    # blocks = "addi a5,a6,1\\nsd a5,-88(s0)\\nlbu a0,0(a6)"
    # blocks = "ld s0,320(sp)\\nld s1,312(sp)\\nld s2,304(sp)\\nld s3,296(sp)\\nld s4,288(sp)\\nld s5,280(sp)\\nld s6,272(sp)\\nld s7,264(sp)\\nld s8,256(sp)\\nld s9,248(sp)\\nld s10,240(sp)\\nld s11,232(sp)\\nsd zero,8(sp)".replace('\\n', '\n')
    # blocks = "lw a5,16(a4)\\naddiw s1,a5,1\\naddi a5,a5,1\\naddi a3,s1,0\\nsub s1,s1,a5\\nsw a3,16(a4)\\nsltu s1,zero,s1\\nld a3,16(s0)\\nld a5,0(a3)".replace('\\n', '\n')
    # blocks = "addi a4,a5,1\nsd a4,8(s0)\nlbu a5,0(a5)\nld a4,72(s1)\nslli a3,s2,0x3\nsltu a5,zero,a5\nadd a4,a4,a3\nsb a5,6(a4)\naddi s2,s2,1\n"
    # blocks = "addi a5,zero,0\nld a4,-96(s0)\nadd a5,a4,a5\nlbu a5,0(a5)\n\n"
    # blocks = "lhu a1,2(sp)\nlui a4,0x1\naddiw a4,a4,-496\nmulw a1,a1,a4\nlhu a0,4(sp)\nlhu a2,6(sp)\nadd a4,s1,s3\nslliw a3,a0,0x4\nsubw a3,a3,a0\nslliw a3,a3,0x2\nslli a4,a4,0x4\nadd a4,s2,a4\nld s5,24(sp)\naddw a3,a3,a1\naddw a3,a2,a3\nmulw a3,a3,a6\nld s6,16(sp)\nsw a3,28(a4)\n"
    # blocks = "slli s10,a3,0x2\nslli a3,a3,0x3\nadd s10,s2,s10\nadd s3,s2,a3\nlw a0,-4(s10)\naddi s10,s10,-4\naddi s3,s3,-8\n"
    # blocks = "addi sp,sp,-32\nsd ra,24(sp)\nsd s0,16(sp)\naddi s0,sp,32\nsd a0,-24(s0)\nld a5,-24(s0)\nld a5,80(a5)\naddi a0,a5,0\nld ra,24(sp)\nld s0,16(sp)\naddi sp,sp,32\n\n"

    blocks = "auipc a5,0x23b\nld a5,896(a5)\nlw a4,0(a5)"
    blocks = "auipc a0,0x24a\naddi a0,a0,1544\nlw a5,0(a0)"
    blocks =  "auipc a4,0x1f1\nld a4,2040(a4)\nld a5,0(a4)"
    blocks = "addi sp,sp,-16\nsd s0,0(sp)\nlui s0,0x387\nlbu a5,1840(s0)\nsd ra,8(sp)"
    blocks = "lui a4,0x2d3\nslli a3,a5,0x20\nsrli a5,a3,0x1e\naddi a4,a4,-1240\nadd a5,a5,a4\nlw a5,0(a5)"
    blocks = "lui a5,0x2a6\naddi a5,a5,1768\nld a4,0(a5)\nsw a0,4(a4)"
    
    blocks = "sd s6,120(gp)\\nsw s2,116(gp)\\nld s8,32(sp)\\nld s7,40(sp)\\nld a5,0(s0)\\nld a4,-952(gp)\\nsd s5,56(a5)\\nld a3,0(s0)\\nld a5,56(a3)\\nld a2,16(a3)"
    blocks = "ld a4,0(a5)\\naddi a2,zero,2\\naddi a3,zero,-1\\nsw a3,16(a5)\\nsw a2,24(a5)\\nld a2,0(a4)\\nld a4,-952(gp)\\nld a3,-688(gp)\\nsd zero,8(a2)\\nld a4,0(a4)\\nsub s1,s1,a3\\nsrai s1,s1,0x3\\nsd s1,8(a4)\\nld a4,0(a5)\\nld a4,0(a4)\\nld a3,-760(gp)\\nld a4,0(a4)\\nld a1,-768(gp)\\naddi a3,a3,4\\nsd a4,-688(gp)\\nld a2,0(a5)\\nld a2,0(a2)\\nld a2,16(a2)\\nslli a2,a2,0x3\\nadd a2,a4,a2\\nsd a2,-696(gp)\\nld a2,0(a5)\\nld a2,0(a2)\\nld s1,8(a2)\\nslli s1,s1,0x3\\nadd s1,a4,s1\\nsd s1,-664(gp)\\nld a2,0(a5)\\nsd a5,-960(gp)\\nsd a3,-760(gp)\\nsd a2,-952(gp)",

    with open("temp.S", 'w', encoding='utf-8') as f:
        f.write(blocks.replace("\\n",'\n'))
    result = transform_for_profiling("temp.S",verbose = True)
    # transform_for_random_scheduling("temp.S", limit=10)
    print(result)

def test_coremark():
    filepath = '/opt/artifact/Documents/raw_data(extract_from_app)/json_new/coremark.json'
    success = 0
    failed = 0

    result_filename = f'/opt/artifact/Documents/se_result/coremark2.json'
    with open(result_filename, 'w', encoding='utf-8') as result_file:
        result_file.write('[\n')

    first_item = True
    idx = 0
    
    with open(filepath, 'r') as f:
        # 解析 JSON 数组中的每个元素
        for block in ijson.items(f, 'item'):
            if block.get('result') is not None:
                idx += 1
                continue
            
            asm = block['asm'].replace('\\n', '\n')
            temp_filename = f'{idx}.S'
            if idx % 100 == 0:
                print(f"Already processed {idx} blocks")

            with open(temp_filename, 'w', encoding='utf-8') as f_temp:
                f_temp.write(asm)

            try:
                result = transform_for_profiling(temp_filename, verbose=0)
                result['id'] = block['id']
                result['function'] = block['function']
                result['asm'] = block['asm']
                if result and result.get('result') is not None:
                    success += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"[FAIL] {idx}.S: {e}")
                result = {'id': block['id'], 'function': block['function'], 'asm': block['asm'], 'result': None}
                failed += 1

            with open(result_filename, 'a', encoding='utf-8') as result_file:
                if not first_item:
                    result_file.write(',\n')
                json.dump(result, result_file, indent=2)
                first_item = False

            rm_file(temp_filename)
            
            # 强制垃圾回收
            import gc
            gc.collect()
            
            # 每处理10个block，等待1秒让系统释放资源
            if (idx + 1) % 10 == 0:
                import time
                time.sleep(1)
            
            idx += 1

    with open(result_filename, 'a', encoding='utf-8') as result_file:
        result_file.write('\n]')

    print(f"\n运行完成：成功 {success} 个，失败 {failed} 个")


def write_batch(batch_results: List[Dict], result_filename: str, first_item: bool) -> bool:
    """写入一批结果到文件"""
    if not batch_results:
        return first_item

    with open(result_filename, 'a', encoding='utf-8') as result_file:
        for result in batch_results:
            if not first_item:
                result_file.write(',\n')
            json.dump(result, result_file, indent=2)
            first_item = False

    return first_item


def process_single_block(block: Dict, idx: int) -> Dict[str, Any]:
    """处理单个数据块"""
    temp_filename = f'temp_{idx}.S'

    try:
        asm_content = block['asm'].replace('\\n', '\n')
        with open(temp_filename, 'w', encoding='utf-8') as f_temp:
            f_temp.write(asm_content)

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(100)
        try:
            result = transform_for_profiling(temp_filename, verbose=0)
        except TimeoutException:
            print(f"[TIMEOUT] 处理块 {idx} 超时")
            result = {}
        finally:
            signal.alarm(0)


        output = {
            'id': block['id'],
            'function': block['function'],
            'asm': block['asm'],  # 保留原始asm字段
            'result': result
        }

        return output

    except Exception as e:
        print(f"[FAIL] 处理块 {idx} 失败: {e}")
        traceback.print_exc()
        return {
            'id': block['id'],
            'function': block['function'],
            'asm': block['asm'],  # 保留原始asm字段
            'result': None,
        }
    finally:
        rm_file(temp_filename)
        gc.collect()


def test_coremark_batched():
    """批量处理的流式处理版本"""
    filepath = '/opt/artifact/Documents/rvmca/tests/spec06_pp_filtered.json'
    result_filename = 'spec06_pp_filtered0427.json'

    # 批次大小配置
    PROCESS_BATCH_SIZE = 25  # 每批处理数量，可根据内存调整
    WRITE_BATCH_SIZE = 10    # 每批写入数量，可根据内存调整

    success = 0
    failed = 0
    idx = 0

    # 初始化结果文件
    with open(result_filename, 'w', encoding='utf-8') as result_file:
        result_file.write('[\n')

    # 写入缓冲区
    write_buffer = []
    first_item = True

    print(f"开始处理文件: {filepath}")
    print(f"批次大小: 处理={PROCESS_BATCH_SIZE}, 写入={WRITE_BATCH_SIZE}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for block in ijson.items(f, 'item'):
                print(block['id'])
                result = process_single_block(block, idx)

                if result.get('result') is not None:
                    success += 1
                else:
                    failed += 1

                # 添加到写入缓冲区
                write_buffer.append(result)

                # 定期写入批次
                if len(write_buffer) >= WRITE_BATCH_SIZE:
                    first_item = write_batch(write_buffer, result_filename, first_item)
                    write_buffer = []
                    print(f"已写入批次，总进度: {idx + 1}, 成功: {success}, 失败: {failed}")

                # 定期垃圾回收
                if (idx + 1) % PROCESS_BATCH_SIZE == 0:
                    print(f"执行垃圾回收，当前内存使用: {get_memory_usage():.2f}MB")
                    gc.collect()
                    print(f"垃圾回收后内存使用: {get_memory_usage():.2f}MB")

                idx += 1

        # 处理剩余未写入的数据
        if write_buffer:
            first_item = write_batch(write_buffer, result_filename, first_item)
            write_buffer = []

    except Exception as e:
        print(f"处理过程中发生错误: {e}")
        traceback.print_exc()

        # 尝试保存已处理的结果
        if write_buffer:
            write_batch(write_buffer, result_filename, first_item)
            write_buffer = []

    finally:
        # 确保文件正确关闭
        with open(result_filename, 'a', encoding='utf-8') as result_file:
            result_file.write('\n]')

        # 最终清理
        write_buffer = None
        gc.collect()

        print(f"\n处理完成！")
        print(f"总计处理: {idx} 个数据块")
        print(f"成功: {success}, 失败: {failed}")
        print(f"结果保存到: {result_filename}")

def get_memory_usage():
    """获取当前进程内存使用（MB）"""
    import psutil
    import os
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

# if __name__ == "__main__":
#     test_onecase()
if __name__ == "__main__":
    # test_polybench()
    # test_onecase()
    # test_coremark()
    # 添加内存监控
    import psutil
    import sys

    def check_memory_limit(limit_gb: float = 16.0):
        """检查内存使用，如果超过限制则警告"""
        memory_usage = get_memory_usage()
        if memory_usage > limit_gb * 1024:
            print(f"警告: 内存使用过高: {memory_usage:.2f}MB")
            return True
        return False


    print("开始批量流式处理...")
    print(f"初始内存使用: {get_memory_usage():.2f}MB")

    try:
        test_coremark_batched()
    except MemoryError as e:
        print(f"内存不足错误: {e}")
        print("建议措施:")
        print("1. 减小 BATCH_SIZE 和 BATCH_WRITE_SIZE")
        print("2. 增加系统交换空间")
        print("3. 在内存更大的机器上运行")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n用户中断处理")
        sys.exit(0)

    print(f"最终内存使用: {get_memory_usage():.2f}MB")
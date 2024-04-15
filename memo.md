vfio-user を使ったデバイス絵ミューレションについて
---

## 調査

まずどう使われているのか？
hw/remote/vfio-user-obj.c のコメント曰く、x-remote えのみサポートされている様子。
↑ server object  とのことなので、これをよしなに使うまたはつけるように修正する。　

-object として指定するっぽいな。
qemu の object とは？

 *     -object x-vfio-user-server,id=<id>,type=unix,path=<socket-path>,
 *             device=<pci-dev-id>

なので、これを他のマシンで使えるようにする必要はある。
でもやりとりについてはそのまま使えると思われる。

やりとり自体は、UDS っぽい。 指定方法がある。

server なので、デバイス側。ほんと？
自分の話で言う、EPC 側


client -(vfio) - server - epc -|H/W S/W 界面|- driver -みたいな感じになる？


qdef_find_recursive() でデバイスを見つけているっぽい.


Root Complex 側については、hw/vfio/pci.c の実装がそれっぽいか？
使い方はまだ不明

qemu build
./configure --enable-vfio-user-server --target-list=x86_64-softmmu

クライアントの実装はまだQEMU にないが、cloud-hypervisor にはあるので、それを使えばいっか。
git@github.com:cloud-hypervisor/cloud-hypervisor.git

README 通りにうごかしたところ linux のコンソールまではいけた。
これと、qemu を繋ぐ方法についてと、custom linux を起動する方法について調べる必要がある。

help をみるに、--user-device を指定することでできそうな雰囲気を感じる。


動作確認ができた。


- qemu
./qemu/build/qemu-system-x86_64 \
                -machine x-remote,vfio-user=on,auto-shutdown=on \
                -device e1000,id=nice \
                -object x-vfio-user-server,id=vfio-srv,type=unix,path=/tmp/vfio-server.sock,device=nice \
                -nographic

- cloud-hypervisor
 ./target/debug/cloud-hypervisor \
        --kernel ./hypervisor-fw \
        --disk path=focal-server-cloudimg-amd64.raw path=/tmp/ubuntu-cloudinit.img \
        --cpus boot=4 \
        --memory size=1024M,shared=on \
        --net "tap=,mac=,ip=,mask=" \
        --user-device "socket=/tmp/vfio-server.sock,id=vfio-srv,pci_segment=0"

## 実装

vfu_object_init_ctx(): QEMU Object(VfuObject) のもつlibvfio-user のコンテキスト(vfu_ctx)を初期化する。
後述のsocket, device の指定は必須みたい。コメントにある
    - o->vfu_ctx = vfu_create_ctx(socket_path)
    - dev = qdev_find_recursive(o->device)
    - dev の動的型チェック
    - vfu_pci_init()
        - pci configuration space を算出(PCI or PCIe)
        - pci config space の確保　
        - vfu_ctx->pci.config_space に保存
    - unplug の時の処理
    - vfu_setup_region
        - いろいろちぇっく
        - pci configuration space のハンドラの設定
            - vfu_object_cfg_access が設定される
    - vfu_setup_device_dma
        - dma_controller_create: どう言うこと?
    - vfu_object_register_bars
        - PCI BAR の設定
    - vfu_object_setup_irqs
        - vfu_setup_device_nr_irqs
        - msi
        - msix
        - vfu_object_setup_msi_cbs
    - reset時のcallbask 設定
    - vfu_realize_ctx
        - vfu_ctx->pci.config_space の下を色々設定してる
    - o->vfu_poll_fd = vfu_get_poll_fd
    - qemu_set_fd_handler(vfu_poll_fd, vfu_object_attach_ctx)
        - vfu_object_attach_ctx
            - vfu_poll_fd のハンドラの削除　
            - vfu_attach_ctx
            - vfu_poll_fd = vfu_get_poll_fd
            - qemu_set_fd_handler(vfu_poll_fd, vfu_object_ctx_run)

なんで、vfu_get_poll_fdを２回やっている？
タイミングで帰ってくる物が変わる実装になっている、
最初はlisten_fd で、attach 読んだ後は、conn_fd となる。
↑これトリッキーすぎるので、リファクタしたい。

vfu_object_set_socket(): 引数の socket を渡された時によばれる。これを基本追っていけばよさそう。
    - vfu_object_init_ctx

vfu_object_set_device : 引数の `device` を設定された時に呼ばれる。 ↑上と両方設定しているが、２回init_ctx()して問題ない？
    - vfu_object_init_ctx
２回読んで問題ない理由は、両方揃うまでreturn するので、最後のやつの時に処理に入る。

vfu_object_machine_done
    - vfu_object_init_ctx

vfu_object_ctx_run: 多分ここがメインの処理
    - 

vfu_tcx->tran がいろいろ抽象化している。実装はどこ？← tran_sock_ops
e.g. vfu_attach_ctx, vfu_get_poll_fd
vfu_create_ctx で設定していた
    

tran_sock_ops は、subprojects/libvfio-user/lib/tran_sock.c にいろいろある。

QEMU の、Object とはなにか。

API としてみた時にどう使うか、
header は？

- libvfio-user <br>
subprojects/libvfio-user/include/libvfio-user.h

vfu_create_ctx()
vfu_pci_init()
vfu_setup_region()
vfu_setup_device_dma()
dma_controller_create() を dma の最大数、最大サイズでやっているだけ。
dma_register, dma_unregister の callback を登録しているので、話の先はそちらっぽい

dma_register (QEMUでは) vfu_dma_info_t に vaddr, iova 等が入ってくるみたい
MemoryRegion を作る
memory_region_init_ram_ptr
pci_device_iommu_address_space
memory_region_add_subregion

vfu_object_register_bars()
vfu_object_setup_irqs()
vfu_setup_device_reset_cb()
vfu_realize_ctx()
実装を見るに、最後の仕上げ。pci config spaceがまだ設定されていなければ確保。BAR の flag を適切に設定。
割り込みもや、config space の capability についても。多分何もなかった場合のチェーンを設定している。
そして、ctx->realized = true にする。

vfu_get_poll_fd()
抽象化のAPI。今回は socket なので、その実装であるtran_sock.cの中身を追う。
ts->conn_fd が有効であれば、ts->conn_fd を、
そうでなければ、 ts->listen_fd を。
なので、vfu_attach_ctx(後述) 後は、通信に用いる conn_fd を、それ以前は、 listen_fd を返す。　

vfu_attach_ctx()
抽象化のAPI。今回は socket なので、その実装であるtran_sock.cの中身を追う。
具体的に読んでいるのは、 accept() その結果を、ts->conn_fd に入れている。
accept() 後は、最初のバージョンチェック等のやり取りをする。

vfu_run_ctx()
ctx->realized が true かどうか。
loop
    ctx->pending.state のチェック（VFU_CTX_PENDING_NONE) の時はエラー（これはどう言うふうに変わる？）
    get_request()
    handle_request()
end loop

handle_request() : RC からの要求。TLP相当だと思われ。
- handle_dma_map()
- handle_region_access() 

逆向きは？　: EP からのTLP. 多分 APIがあるはず。
多分DMAとある周りだと思うが、わかっていないのでこれを明らかにする。

vfu_destroy_ctx()
vfu_object_restore_msi_cbs()


DMA 周りがわからないので、デバイスエミュレーション側で呼び出す、pci_dma_read/write から調査してみる。
include/hw/pci/pci_device.h

pci_dma_read/pci_dma_write
    pci_dma_rw
        dma_memory_rw
            dma_memory_rw_relaxed
                address_space_rw
                    address_space_write
                    address_space_read_full

mr->ops->read が使えるところは使っている。
↑これに vfio の region は登録するのが良さそうな雰囲気を感じるが、実装がどうなっているかについてはこれから調べる。

handle_dma_map
    fd = consume_fd
    dma_controller_add_region
        dma_map_region
            mmap
        dma->regions を更新する。
            ↑多分これをどこかで使っている。
    ctx->dma_register()
        memory_regon_init_ram_ptr
        pci_device_iommu_address_space
        memory_region_add_subregion

↑このながれで登録ができる。

全体の流れを整理すると、
1. vfio-user のプロトコルの VFIO_USER_DMA_MAP が届く (fd と共に）
2. 届いたfd で mmap を行う
3. あたらに Qemu の MemoryRegion を作成して、mmap した領域を登録
4. pci の iommu address space に MemoryRegion を登録

ここまでくると、デバイスのアクセスは、MemoryRegionの仕組みでアクセスされる。



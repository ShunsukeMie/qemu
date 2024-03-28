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



vfu_object_init_ctx(): libvfio-user のコンテキスト(VfuObject*)を初期化する。
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

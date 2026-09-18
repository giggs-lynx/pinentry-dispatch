# pinentry-dispatch

gpg-agent 在需要金鑰密碼時會啟動一支 pinentry 程式來問人。這個專案就是那支程式：它自己不長對話框，
而是判斷「現在是誰、在哪裡要這個密碼」，然後在幾種問法之間挑一種——本機就用 Touch ID 免打，
遠端就在終端機裡問。

## Language

**client**：
發起這次簽章的那個行程（`git`／`gpg`），由 gpg-agent 透過 `OPTION owner` 告知其 pid。
_Avoid_: 使用者、呼叫端、gpg-agent

**本機 client**：
跟這台機器的 GUI 工作階段是同一個人在用的 client。遠端（SSH）進來的 client 不是本機 client，
即使它的行程就跑在這台機器上。
_Avoid_: local、在本地

**階**：
階梯上的一種問法。Touch ID 是內建的一階；`pinentry-curses`、`pinentry-tty` 是外部程式的一階。
_Avoid_: fallback、後備、backend（Touch ID 也是成員，它不是任何東西的後備）

**階梯**：
一份有優先序的候選清單，由上往下找出第一個「環境合格且已安裝」的階，找到就定案——**不是**一階失敗就往下掉的樓梯。
目前固定為 Touch ID → curses → tty，永不包含 pinentry-mac。
_Avoid_: chain、fallback chain、退階（沒有退階這回事）

**路由**：
這次實際選定的那一階。選定發生在對話開始前，一旦選定就由它做到底；同一次對話不會換階。
_Avoid_: 決策、mode

**交棒**：
把 Assuan 對話轉給某個外部程式的階，之後不再收回。只有外部程式的階才談得上交棒。
_Avoid_: delegate 以外的譯法、轉發、proxy（proxy 是手段，交棒是行為）

**拒絕**：
使用者表示「這次不要簽」。拒絕會結束整次簽章，**不會**往下一階走。
_Avoid_: 取消（「取消」在 Assuan 那層另有含義，且系統取消不是拒絕）

**轉向**：
使用者表示「不用這一階、換個方式問我」。轉向會往下一階走。
_Avoid_: fallback、放棄

**覆寫**：
使用者明示指定路由，跳過判斷。與「判斷」互斥：覆寫存在時不做判斷。
_Avoid_: 設定、option

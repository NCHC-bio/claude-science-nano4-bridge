# claude-science-nano4-bridge

[English](README.md) | 繁體中文

每次連線到 nano4 都要回答三個問題：登入方式、iService 密碼、手機上的一次性驗證碼。
程式無法自己回答這些問題，所以沒辦法直接使用 nano4。

這個工具讓**你**親自登入一次。之後 Claude Science 等程式就能透過你的登入使用
nano4，直到你關閉視窗為止。

不需要任何網路或程式的背景知識。

## 需要準備

- 一台 Windows 電腦
- 你的 iService 帳號
- 手機上會顯示一次性驗證碼的驗證 App

---

# 設定步驟

## 1. 安裝 Claude Science

1. 開啟 <https://claude.com/product/claude-science>
2. 點 **Windows** 下載安裝檔，下載完成後按兩下執行，依畫面指示安裝。
3. 開啟 **Claude Science**，依畫面指示登入。

## 2. 按兩下 `start-bridge.cmd`

這就是全部的設定。第一次執行時會自動準備好一切，大約需要幾分鐘：

- 詢問你的 **iService 帳號**：輸入後按 Enter
- Windows 詢問是否允許變更防火牆設定：點 **是**
- 接著要求你登入

如果 Windows 警告不要執行這個檔案，請點 **其他資訊 → 仍要執行**。

## 3. 登入

三個問題，和平常登入 nano4 時一樣：

```
Login method:   輸入 1 後按 Enter
Password:       你的 iService 密碼
OTP:            手機 App 上的六位數字
```

輸入密碼時**畫面上不會出現任何字元**，沒有圓點也沒有星號，這是正常的。

## 4. 在 Claude Science 加入 nano4

只需要做一次。在左側欄開啟 **Customize → Compute**，然後點 **Add SSH host**：

1. 在 **From ~/.ssh/config** 選擇 **`nano4-bridge`**，不用輸入任何東西。
2. 在 **Authentication** 點 **Password**。不要用預設的 **Public key**，它無法連線。
3. 儲存。

接著請 Claude 在 nano4 上執行任何指令。出現密碼輸入框時，在框中輸入你的
**iService 密碼**，不要輸入在對話中。

選填的備註欄可以寫下 Claude 需要知道的叢集資訊，例如：
*Slurm cluster, submit jobs with sbatch.*

**請保持 bridge 視窗開啟。** 關閉視窗就會中斷連線。

---

# 之後每天使用

按兩下 `start-bridge.cmd`，回答三個問題，工作時保持視窗開啟。

其他設定都不用再做。如果更改了 iService 密碼，也要在 Claude Science 裡更新。

---

# 疑難排解

| 看到的狀況 | 怎麼做 |
|---|---|
| Claude 連不上 nano4 | 確認 `start-bridge.cmd` 視窗還開著，連線靠的就是這個視窗。 |
| bridge 視窗不見了 | 再按兩下 `start-bridge.cmd` 並登入。 |
| 視窗出現 `UPSTREAM LOST` | nano4 中斷了連線。關閉視窗後重新啟動。 |
| 顯示防火牆 **Not allowed** | 關閉視窗，再按兩下 `start-bridge.cmd`，Windows 詢問時點 **是**。 |
| 顯示位址已變更 | 不用處理，bridge 會自動更新。如果 Claude 仍然連不上，在 **Customize → Compute** 重新加入主機。 |
| Claude 可以執行指令，但無法上傳或下載檔案 | 等一分鐘，第一次連線還在完成中。如果持續發生，在 **Customize → Compute** 對這台主機點 **Retry probe**。 |
| Claude 要求輸入密碼後被拒絕 | 輸入 iService 密碼，也就是你在 bridge 視窗輸入的那個。 |
| Claude 顯示 `Permission denied (publickey)` | 加入主機時選成了 **Public key**。重新加入並選擇 **Password**。 |
| 其他問題 | 複製視窗中顯示的內容，傳給維護這個工具的人。 |

---

給維護者的技術說明請見[英文版 README](README.md) 的 **Technical notes**。

readme

https://github.com/mzjdy/MobaXterm-Keygen

執行結果沒有反應（沒有輸出任何文字），是因為在 Windows PowerShell 中直接輸入 ./MobaXterm-Keygen.py 時，系統只會用預設關聯的軟體（例如記事本或 VS Code）在背景開啟檔案，而不會透過 Python 解譯器來執行腳本。

修正方法
請在指令前方加上 python 或 py：

PowerShell
python MobaXterm-Keygen.py "abc123" 25.4
或

PowerShell
py MobaXterm-Keygen.py "abc123" 25.4


常見問題排查
若跳出 python : 找不到檔案或程式：
代表電腦尚未安裝 Python，或未將 Python 加入環境變數（PATH）。請前往 Python 官網 下載安裝，安裝時務必勾選 "Add python.exe to PATH"。

成功產出檔案後：
資料夾內會出現 Custom.mxtpro，再依照 README 指示將該檔案複製到 MobaXterm 的安裝目錄（預設為 C:\Program Files (x86)\Mobatek\MobaXterm）即可完成。

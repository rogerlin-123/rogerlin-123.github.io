"""路徑解析:區分「可寫資料目錄」與「唯讀資源目錄」。

- 開發模式:兩者都在源碼所在資料夾
- PyInstaller 打包(onefile 或 onedir):
    data_dir()   = .exe 所在的目錄(使用者放 config.yaml、state.json 等)
    bundle_dir() = onefile 時為 sys._MEIPASS(臨時解壓),onedir 時與 exe 同層
"""
from __future__ import annotations

import sys
from pathlib import Path


def data_dir() -> Path:
    """使用者資料與執行期產物的寫入位置(config / state / log / pid / users)。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def bundle_dir() -> Path:
    """隨執行檔打包的唯讀資源(static/logo.png、favicon.ico)。"""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

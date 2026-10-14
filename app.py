"""APIForge — conception d'API REST en interface graphique Material Design.

Lancer :  python app.py            (application de bureau)
          python app.py --web      (dans le navigateur)
"""
import logging
import sys

import flet as ft

from apiforge.ui.shell import ApiForgeApp


def main(page: ft.Page) -> None:
    ApiForgeApp(page)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    view = ft.AppView.WEB_BROWSER if "--web" in sys.argv else ft.AppView.FLET_APP
    ft.app(target=main, view=view)

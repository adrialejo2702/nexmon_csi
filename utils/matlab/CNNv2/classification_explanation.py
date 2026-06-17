#!/usr/bin/env manim
from manim import *

# coding=utf-8
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# CNN V2 - Classificaciones de votación para la interfaz web de etiquetado
# ----------------------------------------------------------------------
# Este script genera un video explicativo que muestra:
#   • Soft Vote
#   • Hard Vote
#   • Weighted Soft Vote
#   • Adaptive Weighted Soft Vote
# Adaptado al contexto de detección de movimiento con MIMO CSI en zonas
# definidas (1-3) y núcleos MIMO (0,1,2) de tu proyecto.
# ----------------------------------------------------------------------

# ---------- CONFIGURACIÓN DE ESTILOS ----------
# Paleta de colores inspirada en tu UI (tonos cobre y azul)
BG_COLOR = "#1C1C1C"
TEXT_COLOR = "#58C4DD"
VOTE_COLORS = {
    "soft": "#83C167",          # verde suave
    "hard": "#FF6B6B",         # rojo vivo
    "weighted": "#FFFF00",     # amarillo
    "adaptive": "#6BCB77"      # verde-azulado
}
FONT_SIZE_TITLE = 48
FONT_SIZE_BODY = 30
MONO_FONT = "Menlo"

# ---------- ESQUENAS ----------
class TitleScene(Scene):
    def construct(self):
        title = Title(
            "Clasificaciones de Votación en CNN V2",
            font_size=FONT_SIZE_TITLE,
            color=TEXT_COLOR,
            font=MONO_FONT
        )
        self.add_fixed_title(title)
        self.wait(1)

        # Subtítulo explicativo
        subtitle = Text(
            "Cómo se traducen a la interfaz web que muestra resultados de etiquetado",
            font_size=FONT_SIZE_BODY,
            color="#CCCCCC",
            font=MONO_FONT
        )
        subtitle.next_to(title, DOWN, buff=1.0)
        self.add(subtitle)
        self.wait(1)

class SoftVoteScene(Scene):
    def construct(self):
        # Título de la sección
        soft_title = Text(
            "Soft Vote",
            font_size=FONT_SIZE_TITLE - 5,
            color=VOTE_COLORS["soft"],
            font=MONO_FONT,
            weight=BOLD
        )
        self.play(Write(soft_title))
        self.wait(0.5)

        # Descripción breve
        soft_desc = Text(
            "Promedio ponderado de todas las detecciones por zona.\n"
            "Utiliza los scores de cada núcleo MIMO (0,1,2) y los combina\n"
            "según una ponderación derivada del 68% de la ventana métrica.",
            font_size=FONT_SIZE_BODY,
            color="#EEEEEE",
            font=MONO_FONT
        )
        soft_desc.next_to(soft_title, DOWN, buff=0.5)
        self.play(Write(soft_desc))
        self.wait(2)

        # Simulación visual (caja de texto con puntuaciones)
        scores = VGroup(
            *[Text(f"Z{i} Core{j}: {np.random.rand():.2f}", font_size=FONT_SIZE_BODY, color="#CCCCCC")
              for i in range(1, 4) for j in range(3)]
        ).arrange(DOWN, buff=0.3)
        scores.move_to(soft_desc.get_bottom() + 0.5*DOWN)
        self.play(FadeIn(scores, shift=UP, run_time=1))
        self.wait(2)

        # Flecha que indica transición a Hard Vote
        arrow = Arrow(
            start=soft_desc.get_bottom(),
            end=soft_desc.get_bottom() + DOWN*0.3,
            buff=0,
            color=VOTE_COLORS["hard"]
        )
        self.play(Create(arrow))
        self.wait(0.5)

class HardVoteScene(Scene):
    def construct(self):
        hard_title = Text(
            "Hard Vote",
            font_size=FONT_SIZE_TITLE - 5,
            color=VOTE_COLORS["hard"],
            font=MONO_FONT,
            weight=BOLD
        )
        self.play(Write(hard_title))
        self.wait(0.5)

        hard_desc = Text(
            "Detección basada en la mayor puntuación individual.\n"
            "Se elige la zona/núcleo con el score más alto.\n"
            "Muy sensible a falsos positivos en zonas ruidosas.",
            font_size=FONT_SIZE_BODY,
            color="#EEEEEE",
            font=MONO_FONT
        )
        hard_desc.next_to(hard_title, DOWN, buff=0.5)
        self.play(Write(hard_desc))
        self.wait(2)

        # Visual de selección máxima
        max_marker = Circle(
            radius=0.5,
            color=VOTE_COLORS["hard"],
            fill_opacity=0.3
        )
        max_marker.move_to(scores.get_center())
        self.play(Create(max_marker))
        self.wait(1)

class WeightedSoftVoteScene(Scene):
    def construct(self):
        weighted_title = Text(
            "Weighted Soft Vote",
            font_size=FONT_SIZE_TITLE - 5,
            color=VOTE_COLORS["weighted"],
            font=MONO_FONT,
            weight=BOLD
        )
        self.play(Write(weighted_title))
        self.wait(0.5)

        weighted_desc = Text(
            "Promedio ponderado donde cada zona recibe un peso\n"
            "proporcional a su varianza histórica de CSI.\n"
            "Mejora la robustez frente a zonas con poca activity.",
            font_size=FONT_SIZE_BODY,
            color="#EEEEEE",
            font=MONO_FONT
        )
        weighted_desc.next_to(weighted_title, DOWN, buff=0.5)
        self.play(Write(weighted_desc))
        self.wait(2)

        # Ejemplo de imágenes de peso (barras)
        bars = VGroup()
        for i in range(3):
            bar = Rectangle(
                width=0.8,
                height=0.5,
                fill_opacity=0.2,
                color=VOTE_COLORS["weighted"]
            )
            bar.next_to(bars, RIGHT, buff=0.3) if len(bars) == 0 else None
            bars.add(bar)
        bars.arrange(RIGHT, buff=0.4)
        for idx, bar in enumerate(bars):
            bar.width = 0.8 * (idx + 1) / 4  # escala de peso
            bar.move_to(weighted_desc.get_right() + RIGHT * 0.3 + UP * (idx * 0.2))
        self.play(FadeIn(bars, shift=UP, run_time=1))
        self.wait(2)

class AdaptiveWeightedSoftVoteScene(Scene):
    def construct(self):
        adaptive_title = Text(
            "Adaptive Weighted Soft Vote",
            font_size=FONT_SIZE_TITLE - 5,
            color=VOTE_COLORS["adaptive"],
            font=MONO_FONT,
            weight=BOLD
        )
        self.play(Write(adaptive_title))
        self.wait(0.5)

        adaptive_desc = Text(
            "Ajusta dinámicamente los pesos según la actividad\n"
            "detectada en tiempo real.\n"
            "Permite compensar variaciones de canales y ruido.\n"
            "Usa un factor de adaptación α ∈ [0.1, 0.9].",
            font_size=FONT_SIZE_BODY,
            color="#EEEEEE",
            font=MONO_FONT
        )
        adaptive_desc.next_to(adaptive_title, DOWN, buff=0.5)
        self.play(Write(adaptive_desc))
        self.wait(2)

        # Diagrama de adaptación
        alpha_slider = Slider(
            start_value=0.1,
            end_value=0.9,
            length=4,
            background_opacity=0.2,
            fill_opacity=1,
            color="#E0E0E0"
        )
        alpha_slider.add_updater(lambda m: m.set_value(0.5))
        alpha_label = Text(
            "α = 0.5",
            font_size=FONT_SIZE_BODY,
            color="#FFFFFF",
            font=MONO_FONT
        )
        alpha_label.next_to(alpha_slider, UP, buff=0.2)
        self.play(Create(alpha_slider), Write(alpha_label))
        self.wait(2)

# ----------------------------------------------------------------------
# Helper para generar escena principal (selector de votaciones)
# ----------------------------------------------------------------------
def classification_selector():
    scenes = {
        "title": TitleScene(),
        "soft": SoftVoteScene(),
        "hard": HardVoteScene(),
        "weighted": WeightedSoftVoteScene(),
        "adaptive": AdaptiveWeightedSoftVoteScene()
    }
    return scenes

# ----------------------------------------------------------------------
# INSTRUCCIONES DE USO
# ----------------------------------------------------------------------
# 1. Guarda este archivo como classification_explanation.py en la carpeta
#    /Users/adrian/Desktop/TFG/Repos/nexmon_csi_master/utils/matlab/CNNv2/
# 2. Instala Manim Community Edition:
#       pip install manim
# 3. Genera el video (ejemplo 1080p, calidad alta):
#       manim -qh classification_explanation.py classification_selector -o classification_explanation.mp4
# 4. Integra el MP4 en tu interfaz web mediante <video> HTML5:
#       <video controls autoplay loop style="max-width:100%;">
#           <source src="/path/to/classification_explanation.mp4" type="video/mp4">
#       </video>
#
# NOTA: Este script está pensado para ser ejecutado dentro del entorno
# virtual de tu proyecto (`/Users/adrian/Desktop/TFG/Repos/nexmon_csi_master/
# utils/matlab/CNNv2/.venv`). Asegúrate de activar el entorno antes de
# correr Manim.
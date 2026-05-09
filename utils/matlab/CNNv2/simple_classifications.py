from manim import *

class Classifications(Scene):
    def construct(self):
        # Title
        title = Text("CNN V2 - Clasificaciones de votación", font_size=48, color=WHITE)
        self.play(Write(title))
        self.wait(1)

        # Soft Vote
        soft_vote = Text("Soft Vote: promedio ponderado", font_size=36, color=GREEN)
        self.play(Write(soft_vote))
        self.wait(1)

        # Hard Vote
        hard_vote = Text("Hard Vote: máxima puntuación individual", font_size=36, color=RED)
        self.play(Write(hard_vote))
        self.wait(1)

        # Weighted Soft Vote
        weighted_vote = Text("Weighted Soft Vote: promedio con pesos históricos", font_size=36, color=YELLOW)
        self.play(Write(weighted_vote))
        self.wait(1)

        # Adaptive Weighted Soft Vote
        adaptive_vote = Text("Adaptive Weighted Soft Vote: pesos ajustados dinámicamente", font_size=36, color=BLUE)
        self.play(Write(adaptive_vote))
        self.wait(1)
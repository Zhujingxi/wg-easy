use gpui_kit::component::StyledExt;
use gpui_kit::{prelude::*, *};
use std::{cell::Cell, rc::Rc};

struct State {
    focus: FocusHandle,
    contained_focus: Rc<Cell<bool>>,
}

#[derive(IntoElement)]
pub struct FocusScroll {
    id: ElementId,
    child: AnyElement,
    scroll: ScrollHandle,
    style: StyleRefinement,
}

pub fn reveal(
    id: impl Into<ElementId>,
    child: impl IntoElement,
    scroll: &ScrollHandle,
) -> FocusScroll {
    FocusScroll {
        id: id.into(),
        child: child.into_any_element(),
        scroll: scroll.clone(),
        style: StyleRefinement::default(),
    }
}

impl Styled for FocusScroll {
    fn style(&mut self) -> &mut StyleRefinement {
        &mut self.style
    }
}

impl RenderOnce for FocusScroll {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let state = window.use_keyed_state((self.id.clone(), "focus-scroll"), cx, |_, cx| State {
            focus: cx.focus_handle().tab_stop(false),
            contained_focus: Rc::new(Cell::new(false)),
        });
        let state = state.read(cx);
        let focus = state.focus.clone();
        let contained_focus = state.contained_focus.clone();
        let scroll = self.scroll;
        div()
            .on_children_prepainted(move |children, window, cx| {
                let focused = focus.contains_focused(window, cx);
                // Reveal only on focus entry so manual scrolling stays put.
                if contained_focus.replace(focused) || !focused {
                    return;
                }
                let Some(bounds) = children.first() else {
                    return;
                };
                let viewport = scroll.bounds();
                let delta = if bounds.top() < viewport.top() {
                    viewport.top() - bounds.top()
                } else if bounds.bottom() > viewport.bottom() {
                    viewport.bottom() - bounds.bottom()
                } else {
                    return;
                };
                let offset = scroll.offset() + point(px(0.), delta);
                let scroll = scroll.clone();
                window.on_next_frame(move |window, _| {
                    scroll.set_offset(offset);
                    window.refresh();
                });
            })
            .id(self.id)
            .track_focus(&state.focus)
            .child(self.child)
            .refine_style(&self.style)
    }
}

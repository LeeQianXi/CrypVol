//! 桌面界面共用的视觉层级。
use iced::{
    Border, Element, Fill, Theme,
    widget::{button, column, container, scrollable, text, text_input},
};

pub const GAP: u32 = 20;
pub const PAGE_PADDING: u16 = 24;

pub fn centered<'a, M: 'a>(content: impl Into<Element<'a, M>>) -> Element<'a, M> {
    container(scrollable(
        container(content).center_x(Fill).padding(PAGE_PADDING),
    ))
    .center_x(Fill)
    .center_y(Fill)
    .into()
}

pub fn card<'a, M: 'a>(content: impl Into<Element<'a, M>>) -> iced::widget::Container<'a, M> {
    container(content)
        .padding(PAGE_PADDING)
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style {
                background: Some(palette.background.weak.color.into()),
                border: Border {
                    color: palette.background.strong.color,
                    width: 1.0,
                    radius: 16.0.into(),
                },
                ..Default::default()
            }
        })
}

pub fn field<'a, M: 'a>(label: &'a str, input: impl Into<Element<'a, M>>) -> Element<'a, M> {
    column![text(label).size(14), input.into()]
        .spacing(8)
        .into()
}

pub fn hint<'a>(value: impl Into<std::borrow::Cow<'a, str>>) -> iced::widget::Text<'a> {
    text(value.into())
        .size(13)
        .style(|theme: &Theme| text::Style {
            color: Some(theme.extended_palette().background.strong.text),
        })
}

pub fn input<'a, M: Clone + 'a>(placeholder: &str, value: &str) -> iced::widget::TextInput<'a, M> {
    text_input(placeholder, value).padding(12).size(16)
}

pub fn action<'a, M: Clone + 'a>(label: &'a str) -> iced::widget::Button<'a, M> {
    button(text(label).size(15)).padding([12, 18])
}

#[derive(Default)]
pub enum Feedback {
    #[default]
    None,
    Error(String),
    Success(String),
}

impl Feedback {
    pub fn view<'a, M: 'a>(&'a self) -> Element<'a, M> {
        let (message, error) = match self {
            Self::None => return column![].into(),
            Self::Error(message) => (message, true),
            Self::Success(message) => (message, false),
        };
        container(text(message).size(14))
            .width(Fill)
            .padding([12, 16])
            .style(move |theme: &Theme| {
                let palette = theme.extended_palette();
                let pair = if error {
                    palette.danger.weak
                } else {
                    palette.success.weak
                };
                container::Style {
                    background: Some(pair.color.into()),
                    text_color: Some(pair.text),
                    border: Border {
                        radius: 8.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
            .into()
    }
}

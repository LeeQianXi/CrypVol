//! 编辑器、解锁页与密码提示的布局。
use super::{Editor, Message};
use iced::{
    Element, Fill,
    widget::{button, column, container, row, scrollable, text},
};

impl Editor {
    pub fn password_view(&self) -> Element<'_, Message> {
        use crate::appearance::{GAP, PAGE_PADDING, action};
        scrollable(
            container(
                column![
                    text("解锁私钥").size(24),
                    self.credentials.password_view().map(Message::Credentials),
                    row![
                        action("取消")
                            .style(button::secondary)
                            .on_press(Message::CancelUnlock),
                        action("解锁").on_press_maybe(
                            self.credentials.can_unlock().then_some(Message::Unlock)
                        )
                    ]
                    .spacing(12),
                ]
                .spacing(GAP),
            )
            .padding(PAGE_PADDING),
        )
        .height(Fill)
        .into()
    }
    pub fn view(&self) -> Element<'_, Message> {
        iced::widget::responsive(move |size| self.layout(size.width >= 1000.0)).into()
    }
    fn layout(&self, wide: bool) -> Element<'_, Message> {
        use crate::appearance::{GAP, PAGE_PADDING, action, card, centered, field, hint, input};
        let body: Element<'_, Message> = if let Some(document) = &self.document {
            let header = &document.header;
            let identity = card(
                column![
                    text("基本信息").size(20),
                    field(
                        "名称",
                        input("为密钥命名", header.label.as_deref().unwrap_or(""))
                            .on_input(Message::Label)
                    ),
                    field(
                        "描述",
                        input("添加描述", header.description.as_deref().unwrap_or(""))
                            .on_input(Message::Description)
                    ),
                    field(
                        "注释",
                        input("添加注释", header.comment.as_deref().unwrap_or(""))
                            .on_input(Message::Comment)
                    ),
                ]
                .spacing(GAP),
            )
            .width(Fill);
            let protection =
                card(self.protection.view(document).map(Message::Protection)).width(Fill);
            let panels: Element<'_, Message> = if wide {
                row![identity, protection].spacing(GAP).into()
            } else {
                column![identity, protection].spacing(GAP).into()
            };
            let mut content = column![panels].spacing(GAP);
            content = content.push(
                button(if self.details {
                    "收起文件属性"
                } else {
                    "文件属性"
                })
                .style(button::text)
                .on_press(Message::ToggleDetails),
            );
            if self.details {
                content = content.push(
                    card(
                        column![
                            text("文件属性").size(20),
                            field(
                                "创建时间",
                                input(
                                    "例如 2026-11-19T12:00:00+08:00",
                                    header.created_at.as_deref().unwrap_or("")
                                )
                                .on_input(Message::CreatedAt)
                            ),
                            field(
                                "生成器",
                                input("生成器名称", header.generator.as_deref().unwrap_or(""))
                                    .on_input(Message::Generator)
                            ),
                        ]
                        .spacing(GAP),
                    )
                    .width(Fill),
                );
            }
            let filename = document
                .source
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or("新密钥");
            return column![
                container(
                    row![
                        column![
                            text(filename)
                                .size(24)
                                .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
                            hint(if self.dirty {
                                "有未保存的修改"
                            } else {
                                "已保存"
                            })
                        ]
                        .spacing(6)
                        .width(Fill),
                        action("另存为…")
                            .style(button::secondary)
                            .on_press(Message::SaveAs),
                        action("保存").on_press_maybe(self.dirty.then_some(Message::Save)),
                    ]
                    .spacing(12)
                    .align_y(iced::Alignment::Center)
                )
                .padding(PAGE_PADDING),
                scrollable(
                    container(container(content).max_width(1280))
                        .center_x(Fill)
                        .padding([8, PAGE_PADDING])
                )
                .height(Fill),
                container(self.feedback.view()).padding([12, PAGE_PADDING]),
            ]
            .height(Fill)
            .into();
        } else if let Some(preview) = &self.preview {
            card(
                column![
                    text("解锁密钥").size(28),
                    text(
                        preview
                            .source
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned()
                    )
                    .size(16)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
                    self.credentials.view(preview).map(Message::Credentials),
                    if preview.header.key_protection
                        == crypvol_core::crypto::KeyProtection::Password
                    {
                        Element::from(action("解锁").width(Fill).on_press_maybe(
                            self.credentials.can_unlock().then_some(Message::Unlock),
                        ))
                    } else {
                        Element::from(column![])
                    },
                ]
                .spacing(GAP),
            )
            .width(Fill)
            .max_width(460)
            .into()
        } else {
            text("未加载密钥").into()
        };
        centered(body)
    }
}

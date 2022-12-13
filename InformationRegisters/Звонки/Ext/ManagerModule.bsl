﻿Процедура ОбработкаПолученияФормы(ВидФормы,Параметры,ВыбраннаяФорма,ДополнительнаяИнформация,СтандартнаяОбработка)

// Если пользователь открывает форму вида "ФормаЗаписи", то в зависимости от напрвления звонка
// (входящий или исходящий) откроем соответствующую форму
//-------------------------------------------------------------------------------------------------
	Доступно = (ВидФормы = "ФормаЗаписи");
	Доступно = Доступно И (ТипЗнч(Параметры) = Тип("Структура"));
	Доступно = Доступно И (Параметры.Свойство("Ключ") = Истина);

	Если (Доступно = Истина) Тогда
		ЗвонокОбъект = РегистрыСведений.Звонки.СоздатьМенеджерЗаписи();
		ЗвонокОбъект.Сигнатура = ВРег(СокрЛП(Параметры.Ключ.Сигнатура));
		ЗвонокОбъект.Прочитать();

		Если (ЗвонокОбъект.Выбран()) Тогда
			ВыбраннаяФорма = ?(ЗвонокОбъект.ЭтоВходящий,"ФормаВходящего","ФормаИсходящего");
			СтандартнаяОбработка = Ложь;
		КонецЕсли;
	КонецЕсли;
КонецПроцедуры
